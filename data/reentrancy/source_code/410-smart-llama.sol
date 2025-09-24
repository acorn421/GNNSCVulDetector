contract BancorBuyer {

    // Mapping to store user balances
    mapping(address => uint256) public userBalances;

    // Function to execute a purchase on an exchange
    function buyOne(address exchangeAddress, uint256 purchaseAmount, bytes calldata exchangeData) external payable {
        // Execute the external call to the exchange
        require(exchangeAddress.call.value(purchaseAmount)(exchangeData));
        
        // Deduct the purchase amount from the user's balance
        userBalances[msg.sender] = userBalances[msg.sender] - purchaseAmount;
    }
}