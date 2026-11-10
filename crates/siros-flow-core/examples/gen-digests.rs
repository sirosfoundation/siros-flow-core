fn main() {
    let dir = std::path::Path::new("flows");
    let mut map = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yaml") {
            let definition = siros_flow_core::language::FlowDefinition::from_yaml(
                &std::fs::read_to_string(&path).unwrap(),
            )
            .unwrap();
            map.insert(definition.flow.clone(), definition.digest().to_owned());
        }
    }
    println!("{}", serde_json::to_string_pretty(&map).unwrap());
}
