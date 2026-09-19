pub fn toml_path(path: impl AsRef<std::path::Path>) -> String {
    toml::Value::String(path.as_ref().to_string_lossy().into_owned()).to_string()
}
