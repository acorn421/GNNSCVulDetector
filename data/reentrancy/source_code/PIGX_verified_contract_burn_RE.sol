/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notification contract after the balance check but before state updates. This creates a classic time-of-check-time-of-use scenario where the external call can trigger reentrancy, allowing the function to be called again while the original state is still unchanged.
 * 
 * **Specific Changes Made:**
 * 1. Added a conditional external call to `burnListener.onTokenBurn(msg.sender, _value)` after the balance validation but before state modifications
 * 2. The external call is positioned strategically to create a reentrancy window where balanceOf[msg.sender] has not yet been decremented
 * 3. The burnListener address would need to be set through a separate setter function in the contract
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract that implements IBurnListener and sets it as the burnListener
 * 2. **Attack Transaction**: Attacker calls burn() with amount X
 * 3. **During External Call**: The malicious burnListener.onTokenBurn() is triggered
 * 4. **Reentrancy**: The malicious contract calls burn() again with the same amount X
 * 5. **State Inconsistency**: The second call sees the original balance (not yet decremented) and passes the require check
 * 6. **Double Burn**: Both calls complete, burning 2X tokens but only validating once
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires setting up the malicious burnListener contract first (separate transaction)
 * - The exploit depends on the accumulated state from the listener setup
 * - The reentrancy attack leverages the persistent balanceOf state that hasn't been updated yet
 * - Without the prior listener setup, the external call would not trigger the reentrancy
 * 
 * This creates a realistic vulnerability where tokens can be burned beyond the user's actual balance through careful state manipulation across multiple transactions.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-08-26
*/

pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnListener {
    function onTokenBurn(address from, uint256 value) external;
}

contract PIGX {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    address public burnListener;

    function PIGX(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify burn listener before state updates (creates reentrancy window)
        if (burnListener != address(0)) {
            IBurnListener(burnListener).onTokenBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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