contract DaoChallenge {

    // Withdraw specified amount of Ether from the contract
    function withdrawEtherOrThrow(uint256 withdrawalAmount) {
        bool transferSuccess = msg.sender.call.value(withdrawalAmount)();
        if (!transferSuccess) { 
            revert(); 
        }
    }
}