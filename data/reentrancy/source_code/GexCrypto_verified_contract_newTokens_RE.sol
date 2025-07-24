/*
 * ===== SmartInject Injection Details =====
 * Function      : newTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a recipient contract before state updates. The vulnerability requires:
 * 
 * **Changes Made:**
 * 1. Added external call to `ITokenReceiver(_owner).onTokensReceived(msg.sender, _value)` before state modifications
 * 2. Added conditional check `if (_owner.code.length > 0)` to only call contracts
 * 3. Maintained all original functionality and state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Owner deploys malicious contract implementing `ITokenReceiver`
 * - **Transaction 2**: Owner calls `newTokens()` with malicious contract as `_owner`
 * - **Reentrancy Attack**: Malicious contract's `onTokensReceived()` calls back to `newTokens()` before original state updates complete
 * - **State Accumulation**: Multiple reentrant calls inflate `balanceOf` and `totalSupply` before initial transaction completes
 * 
 * **Why Multi-Transaction Required:**
 * 1. **Setup Phase**: Attacker must first deploy malicious contract in separate transaction
 * 2. **State Dependency**: Vulnerability relies on accumulated state changes across multiple reentrant calls
 * 3. **Timing Window**: Each reentrant call operates on stale state before previous updates complete
 * 4. **Exploitation Chain**: Requires sequence of contract deployment → setup → exploitation
 * 
 * **Exploitation Impact:**
 * - Unlimited token minting through reentrancy
 * - Inflated total supply and individual balances
 * - Breaks token economics and supply constraints
 * - Requires multiple coordinated transactions to achieve maximum impact
 * 
 * This creates a realistic vulnerability where the attacker needs to establish state across multiple transactions before the reentrancy can be effectively exploited.
 */
pragma solidity ^0.4.16;

library SafeMath {
    function mul(uint256 a, uint256 b) internal constant returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal constant returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal constant returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal constant returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }
}

interface ITokenReceiver {
    function onTokensReceived(address from, uint256 value) external;
}

contract GexCrypto is owned {
    using SafeMath for uint256;

    string public constant name = "GexCrypto";
    string public constant symbol = "GEX";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    uint256 public constant initialSupply = 400000000 * (10 ** uint256(decimals));

    address public reserveAccount;
    address public generalBounty;
    address public russianBounty;

    uint256 reserveToken;
    uint256 bountyToken;

    mapping (address => bool) public frozenAccount;
    mapping (address => uint256) public balanceOf;

    event Burn(address indexed _from,uint256 _value);
    event FrozenFunds(address _account, bool _frozen);
    event Transfer(address indexed _from,address indexed _to,uint256 _value);

    function GexCrypto() public {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
        bountyTransfers();
    }

    function bountyTransfers() internal {
        reserveAccount = 0x0058106dF1650Bf1AdcB327734e0FbCe1996133f;
        generalBounty = 0x00667a9339FDb56A84Eea687db6B717115e16bE8;
        russianBounty = 0x00E76A4c7c646787631681A41ABa3514A001f4ad;
        reserveToken = ( totalSupply * 13 ) / 100;
        bountyToken = ( totalSupply * 2 ) / 100;

        balanceOf[msg.sender] = totalSupply - reserveToken - bountyToken;
        balanceOf[russianBounty] = bountyToken / 2;
        balanceOf[generalBounty] = bountyToken / 2;
        balanceOf[reserveAccount] = reserveToken;

        emit Transfer(msg.sender, reserveAccount, reserveToken);
        emit Transfer(msg.sender, generalBounty, bountyToken);
        emit Transfer(msg.sender, russianBounty, bountyToken);
    }

    function _transfer(address _from,address _to,uint256 _value) internal {
        require(balanceOf[_from] > _value);
        require(!frozenAccount[_from]);
        require(!frozenAccount[_to]);

        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(_from, _to, _value);
    }

    function transfer(address _to,uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function freezeAccount(address _account, bool _frozen) onlyOwner public {
        frozenAccount[_account] = _frozen;
        emit FrozenFunds(_account, _frozen);
    }

    function burnTokens(uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[msg.sender] > _value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(msg.sender, _value);
        return true;
    }

    function newTokens(address _owner, uint256 _value) onlyOwner public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Vulnerable: External call before state updates
        if (_owner != address(0) && isContract(_owner)) {
            // Notify recipient contract about incoming tokens
            ITokenReceiver(_owner).onTokensReceived(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_owner] = balanceOf[_owner].add(_value);
        totalSupply = totalSupply.add(_value);
        emit Transfer(0, this, _value);
        emit Transfer(this, _owner, _value);
    }

    function escrowAmount(address _account, uint256 _value) onlyOwner public {
        _transfer(msg.sender, _account, _value);
        freezeAccount(_account, true);
    }

    function() public {
        throw;
    }

    // Helper function for contract detection in pre-0.5.0 Solidity
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
