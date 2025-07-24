/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a window where the allowance check passes but the allowance hasn't been decremented yet, allowing malicious contracts to re-enter the function multiple times across different transactions. The vulnerability requires state accumulation - each successful reentrancy call during the external call window can drain more tokens than the original allowance permits. The exploit requires: 1) Initial transaction with malicious recipient contract, 2) Callback during external call that initiates new transferFrom calls, 3) Each subsequent call sees the unchanged allowance from the original transaction, enabling multiple unauthorized transfers that exceed the intended allowance limit.
 */
pragma solidity ^0.4.21;

contract TKTToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function TKTToken() public { // legacy constructor OK for ^0.4.21
        totalSupply = 500000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "TKTSA";
        symbol = "TKT";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        /*
        In Solidity 0.4.x, address.code does not exist. To detect if the recipient is a contract,
        use extcodesize:
        */
        uint256 length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            // _to.call in 0.4.x returns (bool)
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}