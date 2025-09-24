contract Balancer {

    address public contractOwner;
    
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the owner");
        _;
    }

    function executeTransaction(address recipient, uint256 amount, bytes calldata payload) 
        public 
        onlyOwner 
        returns (bool) 
    {
        return recipient.call.value(amount)(payload);
    }
}