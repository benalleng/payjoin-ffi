import base64
from binascii import unhexlify
import os
import sys
import httpx

import payjoin as payjoin
from typing import Optional

# The below sys path setting is required to use the 'payjoin' module in the 'src' directory
# This script is in the 'tests' directory and the 'payjoin' module is in the 'src' directory
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

import hashlib
import unittest
from pprint import *
from bitcoin import SelectParams
from bitcoin.core.script import (
    CScript,
    OP_0,
    SignatureHash,
)
from bitcoin.wallet import *
from bitcoin.rpc import Proxy, hexlify_str, JSONRPCError

SelectParams("regtest")

def get_rpc_credentials_from_cookie(cookie_path):
    """Reads the RPC credentials from the cookie file"""
    with open(cookie_path, "r") as cookie_file:
        credentials = cookie_file.read().strip()
    return credentials.split(":")

# Function to create and load a wallet if it doesn't already exist
def create_and_load_wallet(rpc_connection, wallet_name):
    try:
        # Try to load the wallet using the _call method
        rpc_connection._call("loadwallet", wallet_name)
        print(f"Wallet '{wallet_name}' loaded successfully.")
    except JSONRPCError as e:
        # Check if the error code indicates the wallet does not exist
        if e.error["code"] == -18:  # Wallet not found error code
            # Create the wallet since it does not exist using the _call method
            rpc_connection._call("createwallet", wallet_name)
            print(f"Wallet '{wallet_name}' created and loaded successfully.")
        elif e.error["code"] == -35:  # Wallet already loaded
            print(f"Wallet '{wallet_name}' created and loaded successfully.")


# Set up RPC connections
rpc_user = os.environ.get("RPC_USER", "admin1")
rpc_password = os.environ.get("RPC_PASSWORD", "123")
rpc_host = os.environ.get("RPC_HOST", "localhost")
rpc_port = os.environ.get("RPC_PORT", "18443")
#ensure this is where your access cookie is located
rpc_data_dir = os.environ.get("RPC_DATA_DIR", "~/.bitcoin/regtest") 
cookie_path = os.path.expanduser(os.path.join(rpc_data_dir, ".cookie"))
rpc_user, rpc_password = get_rpc_credentials_from_cookie(cookie_path)

class InMemoryReceiverPersister(payjoin.payjoin_ffi.ReceiverPersister):
    def __init__(self):
        self.receivers = {}

    def save(self, receiver: payjoin.Receiver) -> payjoin.ReceiverToken:
        self.receivers[str(receiver.key())] = receiver.to_json()

        return receiver.key()

    def load(self, token: payjoin.ReceiverToken) -> payjoin.Receiver:
        token = str(token)
        if token not in self.receivers.keys():
            raise ValueError(f"Token not found: {token}")
        return payjoin.Receiver.from_json(self.receivers[token])

class InMemorySenderPersister(payjoin.payjoin_ffi.SenderPersister):
    def __init__(self):
        self.senders = {}

    def save(self, sender: payjoin.Sender) -> payjoin.SenderToken:
        self.senders[str(sender.key())] = sender.to_json()
        return sender.key()
    
    def load(self, token: payjoin.SenderToken) -> payjoin.Sender:
        token = str(token)
        if token not in self.senders.keys():
            raise ValueError(f"Token not found: {token}")
        return payjoin.Sender.from_json(self.senders[token])

def handle_directory_proposal(receiver, proposal, custom_inputs=None):
    # Extract the transaction to broadcast in the failure case
    tx = proposal.extract_tx_to_schedule_broadcast()

    can_broadcast = payjoin.CanBroadcast()
    # Step 1: Check Broadcast Suitability
    maybe_inputs_owned = proposal.check_broadcast_suitability(None, can_broadcast.callback(tx))

    # Step 2: Check if receiver can sign for proposal inputs
    maybe_inputs_seen = maybe_inputs_owned.check_inputs_not_owned(True)

    # Step 3: Check if any inputs have been seen before (non-interactive check)
    outputs_unknown = maybe_inputs_seen.check_no_inputs_seen_before(False)

    # Step 4: Identify receiver's outputs
    wants_outputs = outputs_unknown.identify_receiver_outputs(True)

    # Step 5: Commit outputs
    wants_inputs = wants_outputs.commit_outputs()

    # Step 6: If custom inputs are provided, use them. Otherwise, make a selection.
    if custom_inputs:
        inputs = custom_inputs
    else:
        # List unspent inputs from the receiver
        unspent_inputs = receiver.list_unspent(None, None, None, None, None)
        selected_input = wants_inputs.try_preserving_privacy(unspent_inputs)
        inputs = [selected_input]

    # Step 7: Contribute the inputs and commit them
    provisional_proposal = wants_inputs.contribute_inputs(inputs).commit_inputs()

    # Step 8: Finalize the proposal
    payjoin_proposal = provisional_proposal.finalize_proposal(
        lambda psbt: receiver.wallet_process_psbt(
            psbt.to_string(),
            None,
            None,
            True  # Ensure the receiver properly clears keypaths
        )
    )

    return payjoin_proposal

class TestPayjoin(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize wallets once before all tests
        sender_wallet_name = "sender"
        sender_rpc_url = f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}/wallet/{sender_wallet_name}"
        cls.sender = Proxy(service_url=sender_rpc_url)
        create_and_load_wallet(cls.sender, sender_wallet_name)

        receiver_wallet_name = "receiver"
        receiver_rpc_url = f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}/wallet/{receiver_wallet_name}"
        cls.receiver = Proxy(service_url=receiver_rpc_url)
        create_and_load_wallet(cls.receiver, receiver_wallet_name)
 
    async def test_integration_v2_to_v2(self):
        try:
            receiver_address = payjoin.bitcoin.Address(str(self.receiver.getnewaddress()), payjoin.bitcoin.Network.REGTEST)
            payjoin.init_tracing()
            services = payjoin.TestServices.initialize()

            # agent = services.http_agent()
            services.wait_for_services_ready()
            directory = services.directory_url()
            ohttp_keys = services.fetch_ohttp_keys()

            # **********************
            # Inside the Receiver:
            expiry: Optional[int] = None
            new_receiver = payjoin.NewReceiver(receiver_address, directory.as_string(), ohttp_keys, expiry)
            persister = InMemoryReceiverPersister()
            token = new_receiver.persist(persister)
            session: payjoin.Receiver = payjoin.Receiver.load(token, persister)
            print(f"session: {session.to_json()}")
            # Poll receive request
            ohttp_relay = services.ohttp_relay_url()
            request: payjoin.RequestResponse = session.extract_req(ohttp_relay.as_string())
            agent = httpx.AsyncClient()
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            response_body = session.process_res(response.content, request.client_response)
            # No proposal yet since sender has not responded
            self.assertIsNone(response_body)
            
            # **********************
            # Inside the Sender:
            # Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            pj_uri = session.pj_uri()
            outputs = {}
            outputs[pj_uri.address()] = 50
            psbt = self.sender._call(
                "walletcreatefundedpsbt",
                [],
                outputs,
                0,
                {"lockUnspents": True, "feeRate": 0.000020},
                )["psbt"]
            new_sender = payjoin.SenderBuilder(psbt, pj_uri).build_recommended(1000)
            persister = InMemorySenderPersister()
            token = new_sender.persist(persister)
            req_ctx: payjoin.Sender = payjoin.Sender.load(token, persister)
            request: payjoin.RequestV2PostContext = req_ctx.extract_v2(ohttp_relay)
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            send_ctx: payjoin.V2GetContext = request.context.process_response(response.content)
            # POST Original PSBT

            # **********************
            # Inside the Receiver:

            # GET fallback psbt
            request: payjoin.RequestResponse = session.extract_req(ohttp_relay.as_string())
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            # POST payjoin
            proposal: payjoin.UncheckedProposal = session.process_res(response.content, request.client_response)
            payjoin_proposal: payjoin.PayjoinProposal = handle_directory_proposal(self.receiver, proposal, None)
            request: payjoin.RequestResponse = payjoin_proposal.extract_req(ohttp_relay.as_string())
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            payjoin_proposal.process_res(response, request.client_response)

            # **********************
            # Inside the Sender:
            # Sender checks, signs, finalizes, extracts, and broadcasts
            # Replay post fallback to get the response
            request: payjoin.RequestOhttpContext = send_ctx.extract_req(ohttp_relay.as_string())
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            checked_payjoin_proposal_psbt: Optional[str] = send_ctx.process_response(response.content, request.ohttp_ctx)
            self.assertIsNotNone(checked_payjoin_proposal_psbt)
            payjoin_tx = payjoin.bitcoin.Psbt.extract_tx(checked_payjoin_proposal_psbt)
            self.sender.sendrawtransaction(payjoin_tx)

            # Check resulting transaction and balances
            network_fees = payjoin.bitcoin.blockdata.predicted_tx_weight(payjoin_tx) * 1000;
            # Sender sent the entire value of their utxo to receiver (minus fees)
            self.assertEqual(payjoin_tx.input.len(), 2);
            self.assertEqual(payjoin_tx.output.len(), 1);
            self.assertEqual(self.receiver.getbalance(), payjoin.bitcoin.Amount.from_btc(100.0) - network_fees)
            self.assertEqual(self.sender.getbalance(), payjoin.bitcoin.Amount.from_btc(0.0))
        except Exception as e:
            print("Caught:", e)
            raise

class ProcessPartiallySignedTransactionCallBack:
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, psbt: str):
        try:
            return  self.connection._call(
                "walletprocesspsbt", psbt, True, "NONE", False
            )["psbt"]
        except Exception as e:
            print(f"An error occurred: {e}")
            return None   


class MempoolAcceptanceCallback(payjoin.CanBroadcast):
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, tx):
          try:
                return self.connection._call("testmempoolaccept", [bytes(tx).hex()])[0][
                    "allowed"
                ]
          except Exception as e:
            print(f"An error occurred: {e}")
            return None      


# class OutputOwnershipCallback(IsOutputKnown):
#     def callback(self, outpoint: OutPoint):
#         return False


class ScriptOwnershipCallback(payjoin.IsScriptOwned):
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, script):
        try:
            script = CScript(bytes(script))      
            witness_program = script[2:]   
            address = P2WPKHBitcoinAddress.from_bytes(0, witness_program)
            return self.connection._call("getaddressinfo", str(address))["ismine"]
        except Exception as e:
            print(f"An error occurred: {e}")
            return None



if __name__ == "__main__":
    unittest.main()
