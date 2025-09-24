contract BountyHunt {

    // Mapping to store bounty amounts for each address
    mapping(address => uint) public userBounties;
    
    // Total amount of bounty in the contract
    uint public totalBountyPool;

    // Contract owner address
    address contractOwner;

    // Modifier to restrict access to the owner
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this");
        _;
    }

    // Function to claim the bounty
    function claimBounty() external onlyOwner {
        uint userBalance = userBounties[msg.sender];

        // Transfer the bounty and update state
        if (msg.sender.call.value(userBalance)()) {
          totalBountyPool -= userBalance;
          userBounties[msg.sender] = 0;
        }
    }
}