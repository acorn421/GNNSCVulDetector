/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing the transfer. The vulnerability exploits the fact that allowance is decremented before the external call, creating a window where the state is inconsistent across multiple transactions.
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls transferFrom with a malicious contract as _to
 * 2. **During external call**: Malicious contract's onTokenTransfer function calls transferFrom again
 * 3. **Transaction 2**: Second transferFrom call operates on the already-decremented allowance but before balances are updated
 * 4. **State accumulation**: Multiple calls can drain more tokens than the original allowance permitted
 * 
 * **Why Multiple Transactions Required:**
 * - The vulnerability requires the external call to trigger additional transferFrom calls
 * - Each call decrements the allowance incrementally, creating accumulated state changes
 * - The exploit depends on multiple function invocations operating on persistent state modifications
 * - A single transaction cannot exploit this because the reentrancy depends on the state changes persisting between the allowance update and the balance update phases
 * 
 * **Key Vulnerability Points:**
 * - Allowance is decremented before external call (CEI pattern violation)
 * - External call allows reentrancy during state transition
 * - Multiple transactions can exploit the persistent allowance state changes
 * - The vulnerability creates a time window where state consistency is violated across transaction boundaries
 */
pragma solidity ^0.4.16;

contract CFNDToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function CFNDToken() public {
        totalSupply = 40000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Cryptfunder";
        symbol = "CFND";
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
        
        // Add external call to recipient before completing the transfer
        if (isContract(_to)) {
            // Call recipient contract to notify of incoming transfer
            _to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of call result
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

    // Helper function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
}
