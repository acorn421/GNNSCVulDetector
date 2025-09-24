contract generic_holder {

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    function execute(address target, uint amount, bytes memory data) external onlyOwner returns (bool) {
        return target.call{value: amount}(data);
    }
}