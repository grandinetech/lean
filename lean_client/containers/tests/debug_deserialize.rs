use containers::state::State;
use std::fs;

#[test]
fn debug_deserialize_state() {
    let json_content = fs::read_to_string(
        "../tests/test_vectors/test_blocks/test_sequential_blocks.json"
    ).expect("Failed to read test vector file");
    
    // Try to deserialize just to see where it fails
    let result: Result<serde_json::Value, _> = serde_json::from_str(&json_content);
    
    match result {
        Ok(value) => {
            println!("✓ JSON is valid");
            
            // Try to extract just the pre state
            if let Some(tests) = value.as_object() {
                if let Some((test_name, test_case)) = tests.iter().next() {
                    println!("✓ Found test: {}", test_name);
                    
                    if let Some(pre) = test_case.get("pre") {
                        println!("✓ Found pre state");
                        
                        // Try deserializing field by field
                        if let Some(pre_obj) = pre.as_object() {
                            for (field_name, field_value) in pre_obj.iter() {
                                println!("\nTrying to deserialize field: {}", field_name);
                                println!("Field value type: {}", match field_value {
                                    serde_json::Value::Null => "null",
                                    serde_json::Value::Bool(_) => "bool",
                                    serde_json::Value::Number(_) => "number",
                                    serde_json::Value::String(_) => "string",
                                    serde_json::Value::Array(_) => "array",
                                    serde_json::Value::Object(_) => "object",
                                });
                                
                                if field_value.is_object() {
                                    if let Some(obj) = field_value.as_object() {
                                        println!("Object keys: {:?}", obj.keys().collect::<Vec<_>>());
                                    }
                                }
                            }
                        }
                        
                        // Now try to deserialize the whole state
                        let state_result: Result<State, _> = serde_json::from_value(pre.clone());
                        match state_result {
                            Ok(_) => println!("\n✓ Successfully deserialized State"),
                            Err(e) => {
                                println!("\n✗ Failed to deserialize State");
                                panic!("Failed to deserialize State: {}", e);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => panic!("Invalid JSON: {}", e),
    }
}
