contract TelcoinSaleCapEscrow {

    // Mapping to track deposits by participant address
    mapping(address => uint256) public userDeposits;

    // Function to reject a participant and return their funds
    function reject(address participantAddress) public {
        uint256 amountToReturn = userDeposits[participantAddress];
        require(participantAddress.call.value(amountToReturn)());
        userDeposits[participantAddress] = 0;
    }
}