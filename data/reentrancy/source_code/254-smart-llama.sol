contract BancorBuyer {

    // Mapping to track exchange balances
    mapping(address => uint256) public exchangeBalances;

    // Internal function to execute buy transaction
    function buyInternal(address exchangeAddress, uint256 amount, bytes memory transactionData) internal {
        // Execute the call to the exchange
        require(exchangeAddress.call.value(amount)(transactionData));
        // Update the balance after the transaction
        exchangeBalances[exchangeAddress] = exchangeBalances[exchangeAddress] - amount;
    }

}