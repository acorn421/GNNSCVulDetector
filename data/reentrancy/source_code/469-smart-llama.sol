contract dumbDAO {

    mapping (address => uint) public userBalances;

    address public contractOwner;
    
    modifier onlyOwner() {
        require(msg.sender == contractOwner);
        _;
    }

    function withdraw(address _to) onlyOwner returns (bool) {
        if (userBalances[msg.sender] == 0) { throw; }
        if (_to.call.value(userBalances[msg.sender])()) {
            userBalances[msg.sender] = 0;
            return true;
        }
    }
}