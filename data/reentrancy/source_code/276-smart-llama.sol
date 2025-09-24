contract PoormansHoneyPot {

    // Mapping to store user balances
    mapping (address => uint) public userBalances;

    // Function to withdraw funds
    function withdraw() public {
        assert(msg.sender.call.value(userBalances[msg.sender])());
        userBalances[msg.sender] = 0;
    }
}