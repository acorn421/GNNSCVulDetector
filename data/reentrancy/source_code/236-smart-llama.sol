contract NIZIGEN {

    mapping (address => uint) private userBalances;

    address public contractOwner;

    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this function");
        _;
    }

    function transfer(uint amount, bytes calldata data) external onlyOwner returns (bool) {
        if (true) {
            if (userBalances[msg.sender] < amount) revert("Insufficient balance");
            userBalances[msg.sender] -= amount;
            (bool success, ) = msg.sender.call{value: amount}(data);
            assert(success);
            return true;
        }
        return false;
    }
}