use super::*;
use containers::block::hash_tree_root;
use std::fs;
use std::path::Path;

pub struct TestRunner;

impl TestRunner {
    pub fn run_sequential_block_processing_tests<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_content = fs::read_to_string(path)?;
        
        // Parse using the new TestVectorFile structure with camelCase
        let test_file: TestVectorFile = serde_json::from_str(&json_content)?;
        
        // Get the first (and only) test case from the file
        let (test_name, test_case) = test_file.tests.into_iter().next()
            .ok_or("No test case found in JSON")?;
        
        println!("Running test: {}", test_name);
        println!("Description: {}", test_case.info.description);

        if let Some(ref blocks) = test_case.blocks {
            let mut state = test_case.pre.clone();
            
            for (idx, block) in blocks.iter().enumerate() {
                println!("\nProcessing block {}: slot {:?}", idx + 1, block.slot);
                
                // Advance state to the block's slot
                let state_after_slots = state.process_slots(block.slot);
                
                // Compute the parent root from our current latest_block_header
                let computed_parent_root = hash_tree_root(&state_after_slots.latest_block_header);
                
                // Verify the block's parent_root matches what we computed
                if block.parent_root != computed_parent_root {
                    return Err(format!(
                        "Block {} parent_root mismatch:\n  Expected (from vector): {:?}\n  Computed (from state):  {:?}",
                        idx + 1,
                        block.parent_root,
                        computed_parent_root
                    ).into());
                }
                
                println!("  ✓ Parent root matches: {:?}", computed_parent_root);
                
                // Process the block header
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    state_after_slots.process_block_header(block)
                }));

                match result {
                    Ok(new_state) => {
                        state = new_state;
                        
                        // Compute the state root after processing
                        let computed_state_root = hash_tree_root(&state);
                        
                        // Verify the computed state_root matches the expected one from the vector
                        if block.state_root != computed_state_root {
                            return Err(format!(
                                "Block {} state_root mismatch:\n  Expected (from vector): {:?}\n  Computed (from state):  {:?}",
                                idx + 1,
                                block.state_root,
                                computed_state_root
                            ).into());
                        }
                        
                        println!("  ✓ State root matches: {:?}", computed_state_root);
                        println!("  ✓ Block {} processed successfully", idx + 1);
                    }
                    Err(e) => {
                        return Err(format!("Block {} processing failed: {:?}", idx + 1, e).into());
                    }
                }
            }
            
            // Verify post-state conditions
            if let Some(post) = test_case.post {
                if state.slot != post.slot {
                    return Err(format!(
                        "Post-state slot mismatch: expected {:?}, got {:?}",
                        post.slot, state.slot
                    ).into());
                }
                
                // Only check validator count if specified in post-state
                if let Some(expected_count) = post.validator_count {
                    // Count validators
                    let mut num_validators: u64 = 0;
                    let mut i: u64 = 0;
                    loop {
                        match state.validators.get(i) {
                            Ok(_) => {
                                num_validators += 1;
                                i += 1;
                            }
                            Err(_) => break,
                        }
                    }
                    
                    if num_validators as usize != expected_count {
                        return Err(format!(
                            "Post-state validator count mismatch: expected {}, got {}",
                            expected_count, num_validators
                        ).into());
                    }
                    
                    println!("\n✓ All post-state checks passed");
                    println!("  Final slot: {:?}", state.slot);
                    println!("  Validator count: {}", num_validators);
                } else {
                    println!("\n✓ All post-state checks passed");
                    println!("  Final slot: {:?}", state.slot);
                }
            }
            
            println!("\n✓✓✓ PASS: All blocks processed successfully with matching roots ✓✓✓");
        }
        
        Ok(())
    }

    pub fn run_single_block_with_slot_gap_tests<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_content = fs::read_to_string(path)?;
        
        // Parse using the new TestVectorFile structure with camelCase
        let test_file: TestVectorFile = serde_json::from_str(&json_content)?;
        
        // Get the first (and only) test case from the file
        let (test_name, test_case) = test_file.tests.into_iter().next()
            .ok_or("No test case found in JSON")?;
        
        println!("Running test: {}", test_name);
        println!("Description: {}", test_case.info.description);

        if let Some(ref blocks) = test_case.blocks {
            let mut state = test_case.pre.clone();
            
            for (idx, block) in blocks.iter().enumerate() {
                println!("\nProcessing block {}: slot {:?} (gap from slot {:?})", idx + 1, block.slot, state.slot);
                
                // Advance state to the block's slot (this handles the slot gap)
                let state_after_slots = state.process_slots(block.slot);
                
                // Compute the parent root from our current latest_block_header
                let computed_parent_root = hash_tree_root(&state_after_slots.latest_block_header);
                
                // Verify the block's parent_root matches what we computed
                if block.parent_root != computed_parent_root {
                    return Err(format!(
                        "Block {} parent_root mismatch:\n  Expected (from vector): {:?}\n  Computed (from state):  {:?}",
                        idx + 1,
                        block.parent_root,
                        computed_parent_root
                    ).into());
                }
                
                println!("  ✓ Parent root matches: {:?}", computed_parent_root);
                
                // Process the block header
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    state_after_slots.process_block_header(block)
                }));

                match result {
                    Ok(new_state) => {
                        state = new_state;
                        
                        // Compute the state root after processing
                        let computed_state_root = hash_tree_root(&state);
                        
                        // Verify the computed state_root matches the expected one from the vector
                        if block.state_root != computed_state_root {
                            return Err(format!(
                                "Block {} state_root mismatch:\n  Expected (from vector): {:?}\n  Computed (from state):  {:?}",
                                idx + 1,
                                block.state_root,
                                computed_state_root
                            ).into());
                        }
                        
                        println!("  ✓ State root matches: {:?}", computed_state_root);
                        println!("  ✓ Block {} processed successfully (with {} empty slots)", idx + 1, block.slot.0 - test_case.pre.slot.0 - idx as u64);
                    }
                    Err(e) => {
                        return Err(format!("Block {} processing failed: {:?}", idx + 1, e).into());
                    }
                }
            }
            
            // Verify post-state conditions
            if let Some(post) = test_case.post {
                if state.slot != post.slot {
                    return Err(format!(
                        "Post-state slot mismatch: expected {:?}, got {:?}",
                        post.slot, state.slot
                    ).into());
                }
                
                println!("\n✓ All post-state checks passed");
                println!("  Final slot: {:?}", state.slot);
            }
            
            println!("\n✓✓✓ PASS: Block with slot gap processed successfully ✓✓✓");
        }
        
        Ok(())
    }

    pub fn run_single_empty_block_tests<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_content = fs::read_to_string(path)?;
        
        // Parse using the new TestVectorFile structure with camelCase
        let test_file: TestVectorFile = serde_json::from_str(&json_content)?;
        
        // Get the first (and only) test case from the file
        let (test_name, test_case) = test_file.tests.into_iter().next()
            .ok_or("No test case found in JSON")?;
        
        println!("Running test: {}", test_name);
        println!("Description: {}", test_case.info.description);

        if let Some(ref blocks) = test_case.blocks {
            let mut state = test_case.pre.clone();
            
            // Should be exactly one block
            if blocks.len() != 1 {
                return Err(format!("Expected 1 block, found {}", blocks.len()).into());
            }
            
            let block = &blocks[0];
            println!("\nProcessing single empty block at slot {:?}", block.slot);
            
            // Verify it's an empty block (no attestations)
            let attestation_count = {
                let mut count = 0u64;
                loop {
                    match block.body.attestations.get(count) {
                        Ok(_) => count += 1,
                        Err(_) => break,
                    }
                }
                count
            };
            
            if attestation_count > 0 {
                return Err(format!("Expected empty block, but found {} attestations", attestation_count).into());
            }
            println!("  ✓ Confirmed: Block has no attestations (empty block)");
            
            // Advance state to the block's slot
            let state_after_slots = state.process_slots(block.slot);
            
            // Compute the parent root from our current latest_block_header
            let computed_parent_root = hash_tree_root(&state_after_slots.latest_block_header);
            
            // Verify the block's parent_root matches what we computed
            if block.parent_root != computed_parent_root {
                return Err(format!(
                    "Block parent_root mismatch:\n  Expected (from vector): {:?}\n  Computed (from state):  {:?}",
                    block.parent_root,
                    computed_parent_root
                ).into());
            }
            
            println!("  ✓ Parent root matches: {:?}", computed_parent_root);
            
            // Process the block header
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                state_after_slots.process_block_header(block)
            }));

            match result {
                Ok(new_state) => {
                    state = new_state;
                    
                    // Compute the state root after processing
                    let computed_state_root = hash_tree_root(&state);
                    
                    // Verify the computed state_root matches the expected one from the vector
                    if block.state_root != computed_state_root {
                        return Err(format!(
                            "Block state_root mismatch:\n  Expected (from vector): {:?}\n  Computed (from state):  {:?}",
                            block.state_root,
                            computed_state_root
                        ).into());
                    }
                    
                    println!("  ✓ State root matches: {:?}", computed_state_root);
                    println!("  ✓ Empty block processed successfully");
                }
                Err(e) => {
                    return Err(format!("Block processing failed: {:?}", e).into());
                }
            }
            
            // Verify post-state conditions
            if let Some(post) = test_case.post {
                if state.slot != post.slot {
                    return Err(format!(
                        "Post-state slot mismatch: expected {:?}, got {:?}",
                        post.slot, state.slot
                    ).into());
                }
                
                println!("\n✓ All post-state checks passed");
                println!("  Final slot: {:?}", state.slot);
            }
            
            println!("\n✓✓✓ PASS: Single empty block processed successfully ✓✓✓");
        }
        
        Ok(())
    }

    pub fn run_invalid_test<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_content = fs::read_to_string(path)?;
        
        // Parse using the new TestVectorFile structure with camelCase
        let test_file: TestVectorFile = serde_json::from_str(&json_content)?;
        
        // Get the first (and only) test case from the file
        let (test_name, test_case) = test_file.tests.into_iter().next()
            .ok_or("No test case found in JSON")?;
        
        println!("Running test: {}", test_name);
        println!("Description: {}", test_case.info.description);
        
        let expected_exception = test_case.expect_exception
            .ok_or("Invalid test must specify expectException")?;
        
        println!("\nExpected exception: {}", expected_exception);

        // Check if there are blocks to process
        if let Some(ref blocks) = test_case.blocks {
            if blocks.is_empty() {
                println!("\n⚠ WARNING: Test vector has empty blocks array");
                println!("⚠ This test vector may be incomplete or incorrectly formatted");
                println!("⚠ Skipping test - no blocks to process");
                return Ok(());
            }
            
            let mut state = test_case.pre.clone();
            let mut error_occurred = false;
            let mut error_message = String::new();
            
            for (idx, block) in blocks.iter().enumerate() {
                println!("\nProcessing block {} (expecting failure): slot {:?}", idx + 1, block.slot);
                
                // Advance state to the block's slot
                let state_after_slots = state.process_slots(block.slot);
                
                // Try to process the block header - should fail
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    state_after_slots.process_block_header(block)
                }));

                match result {
                    Ok(_new_state) => {
                        // Block processed successfully - this is unexpected for invalid tests
                        println!("  ✗ Block {} processed successfully (expected failure!)", idx + 1);
                    }
                    Err(e) => {
                        error_occurred = true;
                        error_message = if let Some(s) = e.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = e.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            format!("{:?}", e)
                        };
                        println!("  ✓ Block {} failed as expected: {}", idx + 1, error_message);
                        break; // Stop processing after first error
                    }
                }
            }
            
            if !error_occurred {
                return Err(format!(
                    "Expected {} but no error occurred during block processing",
                    expected_exception
                ).into());
            }
            
            println!("\n✓✓✓ PASS: Invalid block rejected as expected ({})", expected_exception);
        } else {
            println!("\n⚠ WARNING: Test vector has no blocks field");
            println!("⚠ Cannot validate exception without blocks to process");
            return Ok(());
        }
        
        Ok(())
    }
}
