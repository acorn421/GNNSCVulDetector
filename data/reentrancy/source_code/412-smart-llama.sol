contract Attack {

    address private targetContract;

    // Execute step 1 of the attack
    function step1(uint256 attackAmount) payable {
        // Check if contract balance is sufficient
        if (address(this).balance >= attackAmount) {
            // Send specified amount to target contract
            (bool success, ) = targetContract.call{value: attackAmount}("");
            require(success, "Transfer failed");
        }
    }
}