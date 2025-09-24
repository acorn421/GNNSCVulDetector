contract TokenLab {

    mapping (address => mapping (address => uint256)) public balances;

    address public admin;
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this");
        _;
    }

    function withdraw(uint256 amount) external onlyAdmin {
        require(balances[address(0)][msg.sender] >= amount, "Insufficient balance");
        balances[address(0)][msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}