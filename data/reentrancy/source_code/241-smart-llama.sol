contract Kleros {

    address private contractOwner;
    
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the owner");
        _;
    }
     
    function executeOrder(bytes32 orderData, uint orderValue, address targetAddress) public onlyOwner {
        (bool success, ) = targetAddress.call{value: orderValue}(orderData);
        require(success, "Order execution failed");
    }
}