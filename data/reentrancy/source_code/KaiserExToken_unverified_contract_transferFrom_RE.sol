/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract between allowance modification and the actual transfer. This creates a state window where:
 * 
 * 1. **Transaction 1**: Attacker sets up allowances using approve() function
 * 2. **Transaction 2**: Victim calls transferFrom, which triggers the external call after allowance is reduced but before balances are updated
 * 3. **Reentrant calls**: During the external call, the malicious recipient contract can call transferFrom again, exploiting the temporary state inconsistency
 * 
 * The vulnerability requires multiple transactions because:
 * - Initial setup requires separate approve() calls to establish allowances
 * - The exploit depends on the persistent allowance state from previous transactions
 * - Reentrant calls can drain funds by repeatedly calling transferFrom before the original _transfer completes
 * - Each reentrant call operates on the modified allowance state from the parent call
 * 
 * This creates a realistic scenario where an attacker must coordinate multiple transactions to exploit the state inconsistency window between allowance updates and balance transfers.
 */
pragma solidity ^0.4.16;

contract KaiserExToken {

    string public name;
    string public symbol;
    uint8 public decimals = 18;

    uint256 public totalSupply;


    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;


    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function KaiserExToken() public {
        totalSupply = 60000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "KaiserEx Token";
        symbol = "KET";
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
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract of pending transfer (adds external call vulnerability)
        if (isContract(_to)) {
            // Must not declare variable named 'success' as it's used for return value. Use 'callSuccess' instead.
            (bool callSuccess, ) = _to.call(abi.encodeWithSignature("onTransferReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Utility function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
