contract MultiAccess {

    address admin;
    
    modifier onlyAdmin() {
        require(msg.sender == admin);
        _;
    }
    
    function multiAccessCallD(address recipient, uint amount, bytes calldata payload) external onlyAdmin returns(bool) {
        return recipient.call.value(amount)(payload);
    }
}