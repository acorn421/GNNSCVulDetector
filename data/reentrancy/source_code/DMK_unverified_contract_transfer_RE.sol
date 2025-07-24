/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract between the sender's balance deduction and recipient's balance update. This creates a window where the contract state is inconsistent - the sender's balance is already reduced but the recipient's balance hasn't been updated yet. 
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker calls transfer() to send tokens to their malicious contract
 * 2. **During Transaction 1**: The malicious contract's onTokenReceived() is called while sender's balance is deducted but recipient's balance isn't updated yet
 * 3. **Reentrancy**: The malicious contract calls transfer() again during the callback, exploiting the inconsistent state
 * 4. **State Accumulation**: Each nested call further reduces the sender's balance while the recipient's balance updates are delayed
 * 5. **Multiple Rounds**: The attack can span multiple transaction calls, with each building on the state changes from previous calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger reentrancy during the inconsistent state window
 * - Each reentrant call builds upon the state changes from previous calls
 * - The attack effectiveness increases with multiple nested calls across transaction boundaries
 * - The inconsistent state persists between function calls, enabling accumulated exploitation
 * 
 * **Realistic Justification:**
 * The onTokenReceived callback is a common pattern in modern token contracts (similar to ERC777 or ERC1155 hooks) for notifying recipient contracts about incoming transfers. This makes the vulnerability realistic and subtle, as the external call serves a legitimate purpose while creating the security flaw.
 */
pragma solidity ^0.4.18;

contract SafeMath {

    function SafeMath() public {
    }

    function safeAdd(uint256 _x, uint256 _y) internal returns (uint256) {
        uint256 z = _x + _y;
        assert(z >= _x);
        return z;
    }

    function safeSub(uint256 _x, uint256 _y) internal returns (uint256) {
        assert(_x >= _y);
        return _x - _y;
    }

    function safeMul(uint256 _x, uint256 _y) internal returns (uint256) {
        uint256 z = _x * _y;
        assert(_x == 0 || z / _x == _y);
        return z;
    }

}

contract DMK is SafeMath {
    string public constant standard = 'Token 0.1';
    uint8 public constant decimals = 18;

    // you need change the following three values
    string public constant name = 'DMK';
    string public constant symbol = 'DMK';
    uint256 public totalSupply = 413 * 10**8 * 10**uint256(decimals);

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function DMK() public {
        emit Transfer(0x00, msg.sender, totalSupply);
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value)
    public
    returns (bool success)
    {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check for sufficient balance
        require(balanceOf[msg.sender] >= _value);
        
        // Update sender's balance first
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);
        
        // VULNERABILITY: External call before recipient balance update
        // This enables reentrancy during the inconsistent state
        if (isContract(_to)) {
            // Notify recipient contract about incoming transfer
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of call result for usability
        }
        
        // Update recipient's balance after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value)
    public
    returns (bool success)
    {
        allowance[_from][msg.sender] = safeSub(allowance[_from][msg.sender], _value);
        balanceOf[_from] = safeSub(balanceOf[_from], _value);
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)
    public
    returns (bool success)
    {
        // To change the approve amount you first have to reduce the addresses`
        //  allowance to zero by calling `approve(_spender, 0)` if it is not
        //  already 0 to mitigate the race condition described here:
        //  https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // Helper function for detecting if an address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }

    // disable pay ETH to this contract
    function () public payable {
        revert();
    }
}
