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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability leverages the existing tokenRecipient interface to create a realistic transfer hook mechanism.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_to).receiveApproval()` before updating allowance
 * 2. Positioned the external call after the allowance check but before the allowance reduction
 * 3. Used try-catch to make the hook optional and maintain backward compatibility
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: User A approves User B for 100 tokens
 * Transaction 2: User B calls transferFrom with recipient as malicious contract
 * Transaction 3: Malicious contract reenters transferFrom during receiveApproval callback
 * Transaction 4: Second transferFrom call uses the same allowance before it's decremented
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires pre-existing allowance state from a previous approve() transaction
 * - The reentrancy occurs during the callback, allowing manipulation of allowance before it's updated
 * - Multiple transferFrom calls can drain more tokens than the original allowance permitted
 * - The stateful nature of allowances across transactions enables the accumulated exploitation
 * 
 * **Exploitation Flow:**
 * 1. Initial approval transaction sets allowance[victim][attacker] = 100
 * 2. Attacker calls transferFrom(victim, maliciousContract, 100)
 * 3. MaliciousContract.receiveApproval() is called (external call)
 * 4. During callback, maliciousContract reenters transferFrom(victim, attacker, 100)
 * 5. Second call sees original allowance (100) before first call decrements it
 * 6. Result: 200 tokens transferred with only 100 token allowance
 * 
 * This creates a realistic vulnerability where the allowance mechanism can be bypassed through reentrancy, requiring multiple transactions and persistent state to exploit effectively.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract SwarmBzzTokenERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function SwarmBzzTokenERC20(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Note: Solidity 0.4.x does not support try-catch or code inspection
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) private view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
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
