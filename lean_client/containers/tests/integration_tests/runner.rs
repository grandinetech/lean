use super::*;
use std::fs;
use std::path::Path;

pub struct TestRunner;

impl TestRunner {
    pub fn run_sequential_block_processing_tests<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_content = fs::read_to_string(path)?;
        
        // Parse the wrapper structure first
        let wrapper: serde_json::Value = serde_json::from_str(&json_content)?;
        let test_case: TestCase<State> = serde_json::from_value(wrapper["test_case"].clone())?;

            println!("Running sequential block processing test: {}", test_case._info.description);
            
            if let Some(ref blocks) = test_case.blocks {
                let mut state = test_case.pre.clone();
                let mut test_passed = true;
                
                for block in blocks {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        // First process slots to advance to the block's slot
                        let state_with_slots = state.process_slots(block.message.slot);
                        // Then process the block header
                        state_with_slots.process_block_header(&block.message)
                    }));
                    
                    match result {
                        Ok(new_state) => {
                            state = new_state;
                            println!("  Block processed successfully");
                        },
                        Err(_) => {
                            println!("  FAIL: Valid block was rejected");
                            test_passed = false;
                        }
                    }
                }
                
                if test_passed {
                    if let Some(ref expected_post) = test_case.post {
                        if state.slot == expected_post.slot && 
                           state.justifications_validators.len() == expected_post.validator_count{
                            println!("  PASS: Block processing successful");
                        } else {
                            println!("  FAIL: Post-state mismatch");
                            println!("    Expected slot: {:?}, got: {:?}", expected_post.slot, state.slot);
                            println!("    Expected validator_count: {:?}, got: {:?}", 
                                expected_post.validator_count, state.justifications_validators.len());
                        }
                    } else {
                        println!("  PASS: Block processing completed");
                    }
                }
            }
        
        
        Ok(())
    }
/*
    pub fn run_single_block_with_slot_gap_tests<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let yaml_content = fs::read_to_string(path)?;
        let test_vector: TestVector<State> = serde_yaml::from_str(&yaml_content)?;
        
        for (i, test_case) in test_vector.test_cases.iter().enumerate() {
            println!("Running test case {}: {}", i, test_case.description);
            
            if let Some(ref blocks) = test_case.blocks {
                let mut state = test_case.pre.clone();
                let mut test_passed = true;
                
                for block in blocks {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        state.state_transition(block.clone(), true)
                    }));
                    
                    match result {
                        Ok(new_state) => {
                            if test_case.valid {
                                state = new_state;
                            } else {
                                println!("  FAIL: Expected invalid block to be rejected");
                                test_passed = false;
                                break;
                            }
                        },
                        Err(_) => {
                            if !test_case.valid {
                                println!("  PASS: Invalid block correctly rejected");
                                continue;
                            } else {
                                println!("  FAIL: Valid block was rejected");
                                test_passed = false;
                                break;
                            }
                        }
                    }
                }
                
                if test_passed && test_case.valid {
                    if let Some(ref expected_post) = test_case.post {
                        if state.slot == expected_post.slot && 
                           state.latest_justified == expected_post.latest_justified &&
                           state.latest_finalized == expected_post.latest_finalized {
                            println!("  PASS: State transition successful");
                        } else {
                            println!("  FAIL: Post-state mismatch");
                        }
                    } else {
                        println!("  PASS: Block processing completed");
                    }
                }
            }
        }
        
        Ok(())
    }
    
    pub fn run_single_empty_block_tests<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let yaml_content = fs::read_to_string(path)?;
        let test_vector: TestVector<State> = serde_yaml::from_str(&yaml_content)?;
        
        for (i, test_case) in test_vector.test_cases.iter().enumerate() {
            println!("Running vote test {}: {}", i, test_case.description);
            
            if let Some(ref votes) = test_case.votes {
                let state = test_case.pre.clone();
                let mut attestations = ssz::PersistentList::default();
                
                // Convert votes to attestations list
                for (idx, vote) in votes.iter().enumerate() {
                    if idx < 4096 {
                        attestations.push(vote.clone()).unwrap();
                    }
                }
                
                let new_state = state.process_attestations(&attestations);
                
                if let Some(ref expected_post) = test_case.post {
                    if new_state.latest_justified == expected_post.latest_justified &&
                       new_state.latest_finalized == expected_post.latest_finalized {
                        println!("  PASS: Vote processing successful");
                    } else {
                        println!("  FAIL: Vote processing result mismatch");
                        println!("    Expected justified: {:?}", expected_post.latest_justified);
                        println!("    Actual justified: {:?}", new_state.latest_justified);
                    }
                }
            }
        }
        
        Ok(())
    }*/
}
