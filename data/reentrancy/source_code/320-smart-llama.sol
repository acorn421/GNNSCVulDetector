contract TelcoinSaleCapEscrow {

    // Tracks the amount of Ether deposited by each participant
    mapping(address => uint256) public balances;

    // Allows the contract to reject a participant and refund their deposit
    function reject(address participant) public {
        uint256 depositAmount = balances[participant];
        require(depositAmount > 0, "No deposit to refund");
        balances[participant] = 0;
        require(participant.call.value(depositAmount)(), "Refund failed");
    }
}