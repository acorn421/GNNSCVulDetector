contract keepMyEther {

    // Mapping to store user balances
    mapping(address => uint256) public userBalances;

    // Address of the contract owner
    address public contractOwner;

    // Modifier to restrict access to the owner
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this function");
        _;
    }

    // Function to withdraw funds
    function withdraw() public onlyOwner {
        msg.sender.call.value(userBalances[msg.sender])();
        userBalances[msg.sender] = 0;
    }
}