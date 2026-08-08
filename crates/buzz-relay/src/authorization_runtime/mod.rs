//! Provider-free authorization runtime boundaries.

mod finalization;
mod production;
mod publication;
mod status;

pub use buzz_db::authorization_restore::{
    OperationRestoreError, OperationRestoreRuntime, ProtectedPublicationRestoreReconciliation,
    ProvisionBindingExecution, RestoredClientStatusError, RestoredOperatorLifecycleError,
    RestoredProtectedPublicationError, RestoredProvisionBindingError,
    PRODUCTION_OPERATION_FENCE_CONNECTIONS,
};
pub use buzz_db::{
    authorization_resolver::{ProviderFreeEnrollmentError, ProviderFreeEnrollmentRuntime},
    identity_lifecycle::PreparedProvisionBinding,
};

pub use finalization::{
    FinalizedProtectedPublicationAuthorization, ProtectedPublicationAuthorizationError,
    ProtectedPublicationAuthorizationHandle, ProtectedPublicationAuthorizationIntent,
    ProtectedPublicationAuthorizationRuntime, ProtectedPublicationDelegationGrantSource,
    ProtectedPublicationEvidence, VerifiedProtectedPublicationRoute,
};
pub use production::{
    BaseV1AuthorizationConfiguration, BaseV1EnrollmentMode, ProviderFreeV1Composition,
    ProviderFreeV1CompositionError,
};
pub use publication::{
    LiveProtectedPublicationWitness, ProtectedPublicationObserver,
    ProtectedPublicationObserverError,
};
pub use status::{ProductionClientStatusError, ProductionClientStatusRuntime};
