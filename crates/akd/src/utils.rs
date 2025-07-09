//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd

#[allow(unused)]
pub(crate) fn random_label(rng: &mut impl rand::Rng) -> crate::NodeLabel {
    crate::NodeLabel {
        label_val: rng.random::<[u8; 32]>(),
        label_len: 256,
    }
}

/// Macro used for running tests with different configurations
/// NOTE(new_config): When adding new configurations, add them here as well
#[macro_export]
macro_rules! test_config_sync {
    ( $x:ident ) => {
        paste::paste! {
            #[test]
            fn [<$x _ colossus_config>]() {
                $x::<$crate::ColossusConfiguration<$crate::configuration::ExampleLabel>>()
            }
        }
    };
}

/// Macro used for running tests with different configurations
#[macro_export]
macro_rules! test_config {
    ( $x:ident ) => {
        paste::paste! {
            #[tokio::test]
            async fn [<$x _ colossus_config>]() -> Result<(), AkdError> {
                $x::<$crate::ColossusConfiguration<$crate::configuration::ExampleLabel>>().await
            }
        }
    };
}
