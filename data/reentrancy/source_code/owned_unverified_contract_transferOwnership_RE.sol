/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State**: Added `ownershipTransferPending` mapping to track pending ownership transfers across transactions
 * 2. **State Modification Before External Call**: Set `ownershipTransferPending[newOwner] = true` before making the external call
 * 3. **External Call to User-Controlled Contract**: Added `newOwner.call()` to notify the new owner, creating a reentrancy opportunity
 * 4. **Critical State Change After External Call**: Moved `owner = newOwner` assignment to occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1** (Setup Phase):
 * - Attacker deploys a malicious contract with `onOwnershipTransferPending()` function
 * - This function will be called during the ownership transfer process
 * 
 * **Transaction 2** (Exploitation Phase):
 * - Current owner calls `transferOwnership(attackerContract)`
 * - Flow:
 *   1. `ownershipTransferPending[attackerContract] = true` (state set)
 *   2. External call to `attackerContract.onOwnershipTransferPending(currentOwner)`
 *   3. **During this call, the attacker can re-enter `transferOwnership()` with a different address**
 *   4. Since `owner` hasn't been updated yet, the attacker still passes `onlyOwner` check
 *   5. This allows multiple nested ownership transfers before the original call completes
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker needs to deploy the malicious contract first (Transaction 1)
 * - The vulnerability only manifests when the legitimate owner calls `transferOwnership()` (Transaction 2)
 * - The persistent state in `ownershipTransferPending` mapping enables the attack by tracking state across multiple nested calls
 * - Without the setup phase, there's no malicious contract to receive the callback and trigger reentrancy
 * 
 * **Realistic Nature:**
 * - Ownership transfer notifications are common patterns in real smart contracts
 * - The pending state mechanism appears to be a legitimate feature for tracking transfers
 * - The vulnerability is subtle - violating CEI pattern is a common mistake in production code
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public ownershipTransferPending;

    function transferOwnership(address newOwner) onlyOwner public {
        require(newOwner != address(0));
        require(!ownershipTransferPending[newOwner]);

        // Mark transfer as pending before external call
        ownershipTransferPending[newOwner] = true;

        // Notify new owner about pending ownership transfer
        /* In Solidity 0.4.16, 'address.code.length' is not available. We cannot check if an address is a contract during runtime here in a standard way, so we remove that guard. The external call proceeds unconditionally. */
        (bool success, ) = newOwner.call(abi.encodeWithSignature("onOwnershipTransferPending(address)", msg.sender));
        require(success);

        // Transfer ownership after external call (CEI pattern violation)
        owner = newOwner;

        // Clear pending status
        ownershipTransferPending[newOwner] = false;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract DoosToken {
    string public name = 'DOOS';
    string public symbol = 'DOOS';
    uint8 public decimals = 18;
    uint256 public totalSupply = 10000000;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function DoosToken(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
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
        require(_value <= allowance[_from][msg.sender]);
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
