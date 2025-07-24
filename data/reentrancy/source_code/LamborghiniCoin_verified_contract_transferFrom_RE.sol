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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` before state updates
 * 2. The call invokes `onTokenReceived()` function on recipient contract
 * 3. State updates (allowance decrement and balance transfers) occur AFTER the external call
 * 4. No reentrancy guard protection
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract and gets allowance approved
 * 2. **Transaction 1**: Attacker calls transferFrom(), triggers external call to malicious contract
 * 3. **Reentrancy**: Malicious contract calls transferFrom() again with same allowance value
 * 4. **Transaction 2+**: Each reentrant call can transfer tokens before allowance is decremented
 * 5. **State Accumulation**: Multiple transfers occur with single allowance approval
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the persistent allowance state across transactions
 * - Each reentrant call operates on the same allowance value before it's decremented
 * - The attacker needs to set up the malicious recipient contract in advance
 * - Multiple calls are needed to drain more tokens than the original allowance should permit
 * - The accumulated effect of state changes across calls enables the exploit
 * 
 * **Realistic Attack Vector:**
 * - Attacker creates contract implementing onTokenReceived() with reentrancy logic
 * - Token holder approves allowance to attacker
 * - Attacker calls transferFrom() to malicious contract address
 * - Malicious contract re-enters transferFrom() before allowance is updated
 * - Process repeats, allowing transfer of more tokens than approved allowance
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract LamborghiniCoin {
    string public name = "Lamborghini Official Coin"; //Implemented by Nando AEC 2018-05-22
    string public symbol = "LOCC";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function LamborghiniCoin() public {
        totalSupply = 200000000 * 10 ** uint256(18);  
        balanceOf[msg.sender] = totalSupply;         
        name = "Lamborghini Official Coin";           
        symbol = "LOCC";                               
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify recipient before state updates (vulnerability injection)
        if (isContract(_to)) {
            // Call recipient contract's notification function
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of call result
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
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
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                        
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                             
        Burn(_from, _value);
        return true;
    }
}
