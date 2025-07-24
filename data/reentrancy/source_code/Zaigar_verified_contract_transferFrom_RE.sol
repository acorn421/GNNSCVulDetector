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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `approve()` to set allowance for a malicious contract
 * 2. **Transaction 2**: Attacker calls `transferFrom()` which triggers the external call to the recipient contract
 * 3. **During Transaction 2**: The malicious recipient contract's `onTokenTransfer()` function re-enters `transferFrom()` before the allowance is decremented
 * 4. **Exploitation**: The re-entrant call sees the original allowance value and can transfer tokens again
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires pre-existing allowance state from a previous transaction
 * - The exploit depends on accumulated allowance permissions set up in earlier transactions
 * - A single transaction cannot both establish the allowance and exploit the reentrancy simultaneously
 * - The state persistence of the allowance mapping between transactions is crucial for the attack
 * 
 * **Key Vulnerability Elements:**
 * - External call to user-controlled contract (`_to`) before state updates
 * - Allowance state remains unchanged during the external call window
 * - Realistic notification mechanism that could exist in production token contracts
 * - Maintains original function behavior while introducing the security flaw
 */
pragma solidity ^0.4.16;    // Versão Compilador v0.4.16+commit.d7661dd9 - Runs (Optimiser):200 - Optimization Enabled: No // Dev Bth.Solutions
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }
contract Zaigar {
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    constructor() public {
        totalSupply = 1000000000 * 10 ** 8;
        balanceOf[msg.sender] = totalSupply;
        name = "Zaigar";
        symbol = "ZAI";
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
          In Solidity 0.4.x, there is no address.code nor address.code.length. To check if _to is a contract,
          the classic method is using extcodesize assembly. We'll reintroduce that with minimal changes.
        */
        uint codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            // Notify recipient contract about incoming transfer
            // Inline (bool callSuccess,) = low-level .call() not supported in 0.4.16; using .call with no declaration
            _to.call(
                bytes4(keccak256("onTokenTransfer(address,address,uint256)")),
                _from, _to, _value
            );
            // Continue even if notification fails
        }
        // State update happens AFTER external call - vulnerable to reentrancy
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
