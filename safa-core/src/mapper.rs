use crate::config::AmaConfig;
use crate::errors::AmaError;

pub struct DomainMapping {
    pub domain_id: String,
    pub magnitude: u64,
}

pub fn map_action(
    action: &str,
    magnitude: u64,
    config: &AmaConfig,
) -> Result<DomainMapping, AmaError> {
    let domain_entry = config
        .domain_mappings
        .get(action)
        .ok_or_else(|| AmaError::Validation {
            error_class: "unknown_action".into(),
            message: format!("action '{}' not in domains.toml", action),
        })?;

    Ok(DomainMapping {
        domain_id: domain_entry.domain_id.clone(),
        magnitude,
    })
}
