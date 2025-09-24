contract TelcoinSaleCapEscrow {

    // Mapping to track deposits for each participant
    mapping(address => uint256) public participantDeposits;

    // Contract owner address
    address public contractOwner;

    // Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == contractOwner);
        _;
    }

    // Function to reject a participant and refund their deposit
    function reject(address participantAddress) public onlyOwner {
        uint256 depositAmount = participantDeposits[participantAddress];
        require(participantAddress.call.value(depositAmount)());
        participantDeposits[participantAddress] = 0;
    }
}