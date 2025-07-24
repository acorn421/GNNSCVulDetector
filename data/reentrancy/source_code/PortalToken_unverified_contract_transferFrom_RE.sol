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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient contract before the transfer is completed. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **First Transaction**: Attacker calls transferFrom() with a malicious contract as _to. The allowance is decremented, then the malicious contract's onTokenReceived() is called.
 * 
 * 2. **Malicious Contract Behavior**: The onTokenReceived() callback can call transferFrom() again (reentrancy), but since the allowance was already decremented in the first call, this second call will fail and restore the allowance.
 * 
 * 3. **State Manipulation**: The malicious contract can manipulate the allowance state through multiple nested calls, potentially allowing unauthorized transfers by exploiting the allowance restoration mechanism.
 * 
 * 4. **Multi-Transaction Exploitation**: The attacker can set up allowances in previous transactions, then exploit the reentrancy to manipulate the allowance state across multiple calls, enabling transfers that should not be possible.
 * 
 * The vulnerability is stateful because it depends on the allowance state persisting between transactions, and the reentrancy allows manipulation of this state in ways that can be exploited across multiple function calls.
 */
pragma solidity ^0.4.18;

// https://github.com/ethereum/wiki/wiki/Standardized_Contract_APIs#transferable-fungibles-see-erc-20-for-the-latest

contract ERC20Token {
    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Add missing storage declaration for m_allowance
    mapping (address => mapping(address => uint256)) internal m_allowance;

    // Add minimal storage for doTransfer to compile (returns true by default, placeholder)
    function doTransfer(address _from, address _to, uint256 _value) internal returns (bool) { return true; }

    // Get the total token supply
    function totalSupply() constant public returns (uint256 supply);

    // Get the account `balance` of another account with address `_owner`
    function balanceOf(address _owner) constant public returns (uint256 balance);

    // Send `_value` amount of tokens to address `_to`
    function transfer(address _to, uint256 _value) public returns (bool success);

    // Send `_value` amount of tokens from address `_from` to address `_to`
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        if (allowance(_from, msg.sender) < _value) revert();

        m_allowance[_from][msg.sender] -= _value;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient contract before completing the transfer
        if (isContract(_to)) {
            (bool success_, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of notification success
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        if ( !(doTransfer(_from, _to, _value)) ) {
            m_allowance[_from][msg.sender] += _value;
            return false;
        } else {
            return true;
        }
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) public returns (bool success);

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant public returns (uint256 remaining);

    // Helper function to check if target is a contract (for <0.5.0)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

contract PortalToken is ERC20Token {
    address public initialOwner;
    uint256 public supply   = 1000000000 * 10 ** 18;  // 1,000,000,000
    string  public name     = 'PortalToken';
    uint8   public decimals = 18;
    string  public symbol   = 'PORTAL';
    string  public version  = 'v0.2';
    uint    public creationBlock;
    uint    public creationTime;

    mapping (address => uint256) balance;
    // m_allowance inherited from ERC20Token

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function PortalToken() public {
        initialOwner        = msg.sender;
        balance[msg.sender] = supply;
        creationBlock       = block.number;
        creationTime        = block.timestamp;
    }

    function balanceOf(address _account) constant public returns (uint) {
        return balance[_account];
    }

    function totalSupply() constant public returns (uint) {
        return supply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        return doTransfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        if (allowance(_from, msg.sender) < _value) revert();

        m_allowance[_from][msg.sender] -= _value;

        if ( !(doTransfer(_from, _to, _value)) ) {
            m_allowance[_from][msg.sender] += _value;
            return false;
        } else {
            return true;
        }
    }

    function doTransfer(address _from, address _to, uint _value) internal returns (bool success) {
        if (balance[_from] >= _value && balance[_to] + _value >= balance[_to]) {
            balance[_from] -= _value;
            balance[_to] += _value;
            emit Transfer(_from, _to, _value);
            return true;
        } else {
            return false;
        }
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        if ( (_value != 0) && (allowance(msg.sender, _spender) != 0) ) revert();

        m_allowance[msg.sender][_spender] = _value;

        emit Approval(msg.sender, _spender, _value);

        return true;
    }

    function allowance(address _owner, address _spender) constant public returns (uint256) {
        return m_allowance[_owner][_spender];
    }
}
