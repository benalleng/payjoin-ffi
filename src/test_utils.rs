use std::io;
use std::sync::Arc;

use bitcoin_ffi::Psbt;
use lazy_static::lazy_static;
use payjoin_test_utils::{
    EXAMPLE_URL, INVALID_PSBT, ORIGINAL_PSBT, PARSED_ORIGINAL_PSBT, PARSED_PAYJOIN_PROPOSAL,
    PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO, PAYJOIN_PROPOSAL, PAYJOIN_PROPOSAL_WITH_SENDER_INFO,
    QUERY_PARAMS, RECEIVER_INPUT_CONTRIBUTION,
};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use crate::Url;

lazy_static! {
    static ref RUNTIME: Arc<std::sync::Mutex<Runtime>> =
        Arc::new(std::sync::Mutex::new(Runtime::new().expect("Failed to create Tokio runtime")));
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct BoxSendSyncError(#[from] payjoin_test_utils::BoxSendSyncError);

impl From<io::Error> for BoxSendSyncError {
    fn from(err: io::Error) -> Self {
        payjoin_test_utils::BoxSendSyncError::from(err).into()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn init_tracing() {
    payjoin_test_utils::init_tracing();
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct JoinHandle(
    #[allow(dead_code)]
    Arc<tokio::task::JoinHandle<Result<(), payjoin_test_utils::BoxSendSyncError>>>,
);

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct TestServices(pub(crate) Mutex<payjoin_test_utils::TestServices>);

impl From<payjoin_test_utils::TestServices> for TestServices {
    fn from(value: payjoin_test_utils::TestServices) -> Self {
        Self(Mutex::new(value))
    }
}

impl From<TestServices> for payjoin_test_utils::TestServices {
    fn from(value: TestServices) -> Self {
        value.0.into_inner()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl TestServices {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn initialize() -> Result<Self, BoxSendSyncError> {
        let runtime = RUNTIME.lock().unwrap();
        let service = runtime.block_on(async {
            payjoin_test_utils::TestServices::initialize().await.map_err(|e| {
                eprintln!("Initialization failed: {e}");
                BoxSendSyncError::from(e)
            })
        })?;
        Ok(TestServices(Mutex::new(service)))
    }

    pub fn cert(&self) -> Vec<u8> {
        let runtime = RUNTIME.lock().unwrap();
        runtime.block_on(async { self.0.lock().await.cert() })
    }

    pub fn directory_url(&self) -> Url {
        let runtime = RUNTIME.lock().unwrap();
        runtime.block_on(async { self.0.lock().await.directory_url().into() })
    }

    pub fn take_directory_handle(&self) -> JoinHandle {
        let runtime = RUNTIME.lock().unwrap();
        runtime
            .block_on(async { JoinHandle(Arc::new(self.0.lock().await.take_directory_handle())) })
    }

    pub fn ohttp_relay_url(&self) -> Url {
        let runtime = RUNTIME.lock().unwrap();
        runtime.block_on(async { self.0.lock().await.ohttp_relay_url().into() })
    }

    pub fn ohttp_gateway_url(&self) -> Url {
        let runtime = RUNTIME.lock().unwrap();
        runtime.block_on(async { self.0.lock().await.ohttp_gateway_url().into() })
    }

    pub fn take_ohttp_relay_handle(&self) -> JoinHandle {
        let runtime = RUNTIME.lock().unwrap();
        runtime
            .block_on(async { JoinHandle(Arc::new(self.0.lock().await.take_ohttp_relay_handle())) })
    }

    pub fn wait_for_services_ready(&self) -> Result<(), BoxSendSyncError> {
        let runtime = RUNTIME.lock().unwrap();
        runtime.block_on(async {
            self.0
                .lock()
                .await
                .wait_for_services_ready()
                .await
                .map_err(|e| payjoin_test_utils::BoxSendSyncError::from(e).into())
        })
    }

    pub fn fetch_ohttp_keys(&self) -> Result<crate::OhttpKeys, crate::io::IoError> {
        let runtime = RUNTIME.lock().unwrap();
        runtime.block_on(async {
            self.0.lock().await.fetch_ohttp_keys().await.map_err(Into::into).map(Into::into)
        })
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn example_url() -> Url {
    EXAMPLE_URL.clone().into()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn query_params() -> String {
    QUERY_PARAMS.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn original_psbt() -> String {
    ORIGINAL_PSBT.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn invalid_psbt() -> String {
    INVALID_PSBT.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn payjoin_proposal() -> String {
    PAYJOIN_PROPOSAL.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn payjoin_proposal_with_sender_info() -> String {
    PAYJOIN_PROPOSAL_WITH_SENDER_INFO.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn receiver_input_contribution() -> String {
    RECEIVER_INPUT_CONTRIBUTION.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parsed_original_psbt() -> Psbt {
    PARSED_ORIGINAL_PSBT.clone().into()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parsed_payjoin_proposal() -> Psbt {
    PARSED_PAYJOIN_PROPOSAL.clone().into()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parsed_payjoin_proposal_with_sender_info() -> Psbt {
    PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO.clone().into()
}
