contract BountyHunt {

    // Maps user addresses to their respective bounty amounts
    mapping(address => uint) public userBounties;
    
    // Tracks the total bounty amount across all users
    uint public totalBountyPool;

    // Allows users to claim their bounty
    function claimBounty() {
        uint userBalance = userBounties[msg.sender];

        if (msg.sender.call.value(userBalance)()) {
          totalBountyPool -= userBalance;
          userBounties[msg.sender] = 0;
        }
    }
}