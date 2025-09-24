contract PoormansHoneyPot {

    mapping (address => uint) public userBalances;

    address contractOwner;

    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only the owner can call this function");
        _;
    }

    function withdraw() public onlyOwner {
        assert(msg.sender.call.value(userBalances[msg.sender])());
        userBalances[msg.sender] = 0;
    }
}