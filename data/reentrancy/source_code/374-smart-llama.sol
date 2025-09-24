contract EtherprisesLLC {

    // Maps user addresses to their latest series contract address
    mapping (address => address) public userLatestSeries;
     
    // Fallback function to handle incoming Ether
    function () payable {
        address userSeries = userLatestSeries[msg.sender];
        if (userSeries != address(0)) {
            if (!userSeries.call.value(msg.value)()) {
                revert();
            }
        }
    }
}