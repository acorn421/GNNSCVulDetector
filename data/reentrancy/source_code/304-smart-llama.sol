contract TokenBank {

    mapping (address => uint) public balances;

    address public admin;
    
    modifier onlyAdmin() {
        require(msg.sender == admin);
        _;
    }
    
    function withdrawToAddress(address _recipient, uint _amount) public onlyAdmin payable {
        if(balances[msg.sender] > 0) {
            if(balances[_recipient] >= _amount) {
                _recipient.call.value(_amount)();
                balances[_recipient] -= _amount;
            }
        }
    }
}