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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added an external call to `_to.call()` to notify the recipient contract of incoming tokens
 * 2. This call happens BEFORE the allowance is decremented, creating a vulnerable window
 * 3. The external call allows the recipient contract to re-enter the function while allowance is still unchanged
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 * - **During Transaction 1**: The malicious contract's `onTokenReceived()` function is called
 * - **Re-entry**: The malicious contract calls `transferFrom()` again with the same parameters
 * - **Transaction 2** (re-entrant): Since allowance hasn't been decremented yet, the second call passes the `require` check
 * - **State Accumulation**: Multiple re-entrant calls can drain allowance before any state updates occur
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger a callback that initiates additional transactions
 * - Each re-entrant call creates a new transaction context where the allowance check can be bypassed
 * - The exploit depends on the accumulated effect of multiple calls executing before the first one completes its state updates
 * - Single transaction exploitation is impossible because the re-entrancy needs to accumulate calls that each pass the allowance check
 * 
 * This creates a realistic scenario where a malicious contract can exploit the window between the external call and state update to drain allowances through multiple re-entrant calls.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/*
*ERC20
*
*/
contract ASSET {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        
        uint256 public totalSupply; 
        uint256 public total = 1000000000;

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);
        event Burn(address indexed from, uint256 value);

        constructor( ) public {
                totalSupply = total * 10 ** uint256(decimals);
                balanceOf[msg.sender] = totalSupply;
                name = "ASSET"; 
                symbol = "ASSET";
        }

     function _transfer(address _from, address _to, uint _value) internal {
    
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
        
        // Call recipient to notify of incoming transfer - vulnerable to reentrancy
        if (isContract(_to)) {
            // Use different variable name to avoid shadowing
            bool callSuccess = _to.call(
                abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value)
            );
            // Continue execution regardless of call success
        }
        
        // State update happens AFTER external call - vulnerable window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
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
