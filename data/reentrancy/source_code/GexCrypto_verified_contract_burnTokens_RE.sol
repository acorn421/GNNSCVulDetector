/*
 * ===== SmartInject Injection Details =====
 * Function      : burnTokens
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled notification contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `burnNotificationContract.onBurnInitiated()` before state modifications
 * 2. The call occurs after balance validation but before balance/supply updates
 * 3. This creates a window where contract state is inconsistent during the external call
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Owner calls `burnTokens()` with legitimate burn amount
 *    - External call to malicious notification contract triggers
 *    - During callback, attacker has access to pre-burn state (higher balance, higher totalSupply)
 *    - Attacker can call other contract functions (like `transfer`, `newTokens`) with inflated values
 *    - State changes from these calls persist after the burn completes
 * 
 * 2. **Transaction 2+**: Attacker continues exploitation using accumulated advantages
 *    - Previous transaction left contract in compromised state
 *    - Attacker can repeat the attack or exploit the accumulated state inconsistencies
 *    - Each transaction builds upon previous state manipulations
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits persistent state changes across transaction boundaries
 * - Each reentrancy creates lasting effects that compound over multiple transactions
 * - Single-transaction exploitation is limited by gas constraints and atomic reversion
 * - The accumulated state manipulation requires multiple calls to maximize damage
 * 
 * **Realistic Integration:**
 * - Burn notifications are common in DeFi for tracking token destruction
 * - External oracles often need to be notified of supply changes
 * - Cross-chain bridges require burn confirmations
 * - This pattern appears natural and maintains function semantics
 * 
 * The vulnerability is subtle, stateful, and requires careful orchestration across multiple transactions to fully exploit the persistent state inconsistencies.
 */
pragma solidity ^0.4.16;

library SafeMath {
	function mul(uint256 a, uint256 b) internal constant returns (uint256) {
		uint256 c = a * b;
		assert(a == 0 || c / a == b);
		return c;
	}

	function div(uint256 a, uint256 b) internal constant returns (uint256) {
		// assert(b > 0); // Solidity automatically throws when dividing by 0
		uint256 c = a / b;
		// assert(a == b * c + a % b); // There is no case in which this doesn't hold
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

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }
}

interface IBurnNotification {
    function onBurnInitiated(address from, uint256 value) external;
}

contract GexCrypto is owned {
    using SafeMath for uint256;

    // Token Variables Initialization
    string public constant name = "GexCrypto";
    string public constant symbol = "GEX";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    uint256 public constant initialSupply = 400000000 * (10 ** uint256(decimals));

    address public reserveAccount;
    address public generalBounty;
    address public russianBounty;

    // Declare burnNotificationContract as required for the vulnerability
    address public burnNotificationContract;

    uint256 reserveToken;
    uint256 bountyToken;

    mapping (address => bool) public frozenAccount;
    mapping (address => uint256) public balanceOf;

    event Burn(address indexed _from,uint256 _value);
    event FrozenFunds(address _account, bool _frozen);
    event Transfer(address indexed _from,address indexed _to,uint256 _value);

    constructor() public {
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

        Transfer(msg.sender,reserveAccount,reserveToken);
        Transfer(msg.sender,generalBounty,bountyToken);
        Transfer(msg.sender,russianBounty,bountyToken);
    }

    function _transfer(address _from,address _to,uint256 _value) internal {
        require(balanceOf[_from] > _value);
        require(!frozenAccount[_from]);
        require(!frozenAccount[_to]);

        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        Transfer(_from, _to, _value);
    }

    function transfer(address _to,uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function freezeAccount(address _account, bool _frozen) public onlyOwner {
        frozenAccount[_account] = _frozen;
        FrozenFunds(_account, _frozen);
    }

    function burnTokens(uint256 _value) public onlyOwner returns (bool success) {
        require(balanceOf[msg.sender] > _value);
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state updates - vulnerable to reentrancy
        if(burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).onBurnInitiated(msg.sender, _value);
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        Burn(msg.sender,_value);

        return true;
    }

    function newTokens(address _owner, uint256 _value) public onlyOwner {
        balanceOf[_owner] = balanceOf[_owner].add(_value);
        totalSupply = totalSupply.add(_value);
        Transfer(0, this, _value);
        Transfer(this, _owner, _value);
    }

    function escrowAmount(address _account, uint256 _value) public onlyOwner {
        _transfer(msg.sender, _account, _value);
        freezeAccount(_account, true);
    }

    function () public {
        revert();
    }
}
