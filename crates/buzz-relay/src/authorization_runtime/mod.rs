//! Provider-free authorization runtime boundaries.

mod finalization;
mod publication;

pub use buzz_db::authorization_restore::{
    OperationRestoreError, OperationRestoreRuntime, ProtectedPublicationRestoreReconciliation,
    RestoredProtectedPublicationError, PRODUCTION_OPERATION_FENCE_CONNECTIONS,
};

pub use finalization::{
    FinalizedProtectedPublicationAuthorization, ProtectedPublicationAuthorizationError,
    ProtectedPublicationAuthorizationHandle, ProtectedPublicationAuthorizationIntent,
    ProtectedPublicationAuthorizationRuntime, ProtectedPublicationDelegationGrantSource,
    ProtectedPublicationEvidence, VerifiedProtectedPublicationRoute,
};
pub use publication::{
    LiveProtectedPublicationWitness, ProtectedPublicationObserver,
    ProtectedPublicationObserverError,
};
