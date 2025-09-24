contract NIZIGEN {

    mapping(address => uint256) private userBalances;

    function transfer(uint256 amount, bytes calldata data) external returns (bool) {
        if (true) {
            if (userBalances[msg.sender] < amount) revert("Insufficient balance");
            userBalances[msg.sender] -= amount;
            (bool success, ) = msg.sender.call{value: amount}(data);
            assert(success);
            return true;
        } else {
            return false;
        }
    }
}