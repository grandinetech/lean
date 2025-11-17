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

    /// Generic test runner for block processing test vectors
    /// Handles all test vectors from test_blocks directory
    pub fn run_block_processing_test<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_content = fs::read_to_string(path.as_ref())?;
        
        // Parse using the TestVectorFile structure with camelCase
        let test_file: TestVectorFile = serde_json::from_str(&json_content)?;
        
        // Get the first (and only) test case from the file
        let (test_name, test_case) = test_file.tests.into_iter().next()
            .ok_or("No test case found in JSON")?;
        
        println!("\n{}: {}", test_name, test_case.info.description);

        // Check if this is an invalid/exception test
        if let Some(ref exception) = test_case.expect_exception {
            println!("  Expecting exception: {}", exception);
            let result = Self::run_invalid_block_test(test_case);
            if result.is_ok() {
                println!("\n\x1b[32m✓ PASS\x1b[0m\n");
            }
            return result;
        }

        // Valid test case - process blocks normally
        if let Some(ref blocks) = test_case.blocks {
            if blocks.is_empty() {
                return Self::verify_genesis_state(test_case);
            }

            let mut state = test_case.pre.clone();
            
            for (idx, block) in blocks.iter().enumerate() {
                // Check if this is a gap (missed slots)
                let gap_size = if idx == 0 {
                    block.slot.0 - state.slot.0
                } else {
                    block.slot.0 - state.slot.0 - 1
                };
                
                if gap_size > 0 {
                    println!("  Block {}: slot {} (gap: {} empty slots)", idx + 1, block.slot.0, gap_size);
                } else {
                    println!("  Block {}: slot {}", idx + 1, block.slot.0);
                }
                
                // Advance state to the block's slot
                let state_after_slots = state.process_slots(block.slot);
                
                // Compute the parent root from our current latest_block_header
                let computed_parent_root = hash_tree_root(&state_after_slots.latest_block_header);
                
                // Verify the block's parent_root matches what we computed
                if block.parent_root != computed_parent_root {
                    println!("    \x1b[31m✗ FAIL: Parent root mismatch\x1b[0m");
                    println!("       Expected: {:?}", block.parent_root);
                    println!("       Got:      {:?}\n", computed_parent_root);
                    return Err(format!("Block {} parent_root mismatch", idx + 1).into());
                }
                
                // Check if block is empty (no attestations)
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
                
                // Process the full block (header + operations)
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    state_after_slots.process_block(block)
                }));

                match result {
                    Ok(new_state) => {
                        state = new_state;
                        
                        // Compute the state root after processing
                        let computed_state_root = hash_tree_root(&state);
                        
                        // Verify the computed state_root matches the expected one from the block
                        if block.state_root != computed_state_root {
                            println!("    \x1b[31m✗ FAIL: State root mismatch\x1b[0m");
                            println!("       Expected: {:?}", block.state_root);
                            println!("       Got:      {:?}\n", computed_state_root);
                            return Err(format!("Block {} state_root mismatch", idx + 1).into());
                        }
                        
                        if attestation_count > 0 {
                            println!("    ✓ Processed with {} attestation(s)", attestation_count);
                        } else {
                            println!("    ✓ Processed (empty block)");
                        }
                    }
                    Err(e) => {
                        println!("    \x1b[31m✗ FAIL: Processing failed\x1b[0m");
                        println!("       Error: {:?}\n", e);
                        return Err(format!("Block {} processing failed", idx + 1).into());
                    }
                }
            }
            
            // Verify post-state conditions
            Self::verify_post_state(&state, &test_case)?;
            
            println!("\n\x1b[32m✓ PASS\x1b[0m\n");
        }
        
        Ok(())
    }

    /// Test runner for genesis state test vectors
    /// Handles test vectors from test_genesis directory
    pub fn run_genesis_test<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_content = fs::read_to_string(path.as_ref())?;
        
        // Parse using the TestVectorFile structure
        let test_file: TestVectorFile = serde_json::from_str(&json_content)?;
        
        // Get the first (and only) test case from the file
        let (test_name, test_case) = test_file.tests.into_iter().next()
            .ok_or("No test case found in JSON")?;
        
        println!("\n{}: {}", test_name, test_case.info.description);

        let state = &test_case.pre;
        
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
        println!("  Genesis time: {}, slot: {}, validators: {}", state.config.genesis_time, state.slot.0, num_validators);
        
        // Verify it's at genesis (slot 0)
        if state.slot.0 != 0 {
            return Err(format!("Expected genesis at slot 0, got slot {}", state.slot.0).into());
        }
        
        // Verify checkpoint initialization
        if state.latest_justified.slot.0 != 0 {
            return Err(format!("Expected latest_justified at slot 0, got {}", state.latest_justified.slot.0).into());
        }
        
        if state.latest_finalized.slot.0 != 0 {
            return Err(format!("Expected latest_finalized at slot 0, got {}", state.latest_finalized.slot.0).into());
        }
        
        // Verify empty historical data
        let has_history = state.historical_block_hashes.get(0).is_ok();
        if has_history {
            return Err("Expected empty historical block hashes at genesis".into());
        }
        
        println!("  ✓ Genesis state validated");
        
        // Verify post-state if present
        if test_case.post.is_some() {
            Self::verify_post_state(state, &test_case)?;
        }
        
        println!("\n\x1b[32m✓ PASS\x1b[0m\n");
        
        Ok(())
    }

    /// Helper: Run invalid block test (expecting exception)
    fn run_invalid_block_test(test_case: TestCase<State>) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref blocks) = test_case.blocks {
            if blocks.is_empty() {
                println!("  WARNING: Empty blocks array - cannot test invalid block");
                return Ok(());
            }

            let state = test_case.pre.clone();
            let mut error_occurred = false;
            
            for (idx, block) in blocks.iter().enumerate() {
                println!("  Block {}: slot {}", idx + 1, block.slot.0);
                
                // Advance state to the block's slot
                let state_after_slots = state.process_slots(block.slot);
                
                // Try to process the full block (header + body) - we expect this to fail
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    state_after_slots.process_block(block)
                }));

                match result {
                    Ok(_) => {
                        println!("    \x1b[31m✗ FAIL: Block processed successfully - but should have failed!\x1b[0m\n");
                        return Err("Expected block processing to fail, but it succeeded".into());
                    }
                    Err(e) => {
                        error_occurred = true;
                        let error_message = if let Some(s) = e.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = e.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            format!("{:?}", e)
                        };
                        println!("    ✓ Correctly rejected: {}", error_message);
                        break; // Stop at first error
                    }
                }
            }
            
            if !error_occurred {
                return Err("Expected an exception but all blocks processed successfully".into());
            }
        }
        
        Ok(())
    }

    /// Helper: Verify genesis state only (no blocks)
    fn verify_genesis_state(test_case: TestCase<State>) -> Result<(), Box<dyn std::error::Error>> {
        let state = &test_case.pre;
        
        // Verify post-state if present
        Self::verify_post_state(state, &test_case)?;
        
        Ok(())
    }

    /// Helper: Verify post-state conditions
    fn verify_post_state(state: &State, test_case: &TestCase<State>) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref post) = test_case.post {
            // Verify slot
            if state.slot != post.slot {
                return Err(format!(
                    "Post-state slot mismatch: expected {:?}, got {:?}",
                    post.slot, state.slot
                ).into());
            }
            
            // Verify validator count if specified
            if let Some(expected_count) = post.validator_count {
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
                println!("  ✓ Post-state verified: slot {}, {} validators", state.slot.0, num_validators);
            } else {
                println!("  ✓ Post-state verified: slot {}", state.slot.0);
            }
        }
        
        Ok(())
    }

}
