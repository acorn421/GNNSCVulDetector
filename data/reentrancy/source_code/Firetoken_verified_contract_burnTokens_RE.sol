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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn registry before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added an external call to `BurnRegistry(burnRegistry).notifyBurn(msg.sender, _value)` after the require check but before state updates
 * 2. This violates the Checks-Effects-Interactions pattern by placing an external call between checks and effects
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: The attacker first deploys a malicious contract that implements the BurnRegistry interface and sets it as the burnRegistry
 * 2. **First Burn Transaction**: When burnTokens is called, the external call to notifyBurn allows the malicious contract to reenter
 * 3. **Reentrancy Exploitation**: The malicious contract can call burnTokens again during the callback, exploiting the fact that balanceOf hasn't been updated yet
 * 4. **State Accumulation**: Each reentrant call sees the original balance, allowing multiple burns of the same tokens
 * 5. **Final State**: After all reentrant calls complete, the state updates occur, but more tokens have been burned than should be possible
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker needs a separate transaction to set up the malicious burnRegistry contract
 * - The vulnerability depends on accumulated state changes from multiple reentrant calls within the same transaction tree
 * - The exploit requires the external contract to be in place before the burn operation begins
 * - The stateful nature means each reentrant call builds upon the previous ones, creating a compound effect
 * 
 * **Additional Required Contract State:**
 * - `address public burnRegistry;` - state variable to store the registry address
 * - `interface BurnRegistry { function notifyBurn(address burner, uint256 amount) external; }` - interface definition
 * 
 * This creates a realistic vulnerability where the external notification mechanism becomes an attack vector through reentrancy.
 */
pragma solidity ^0.4.18;

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

library SafeMath {
	function mul(uint256 a, uint256 b) internal pure returns (uint256) {
		uint256 c = a * b;
		assert(a == 0 || c / a == b);
		return c;
	}

	function div(uint256 a, uint256 b) internal pure returns (uint256) {
		uint256 c = a / b;
		return c;
	}

	function sub(uint256 a, uint256 b) internal pure returns (uint256) {
		assert(b <= a);
		return a - b;
	}

	function add(uint256 a, uint256 b) internal pure returns (uint256) {
		uint256 c = a + b;
		assert(c >= a);
		return c;
	}
}

interface BurnRegistry {
    function notifyBurn(address burner, uint256 value) external;
}

contract Firetoken is owned {
    using SafeMath for uint256;

    // Token Variables Initialization
    string public constant name = "Firetoken";
    string public constant symbol = "FPWR";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    uint256 public constant initialSupply = 18000000 * (10 ** uint256(decimals));

    address public marketingReserve;
    address public devteamReserve;
    address public bountyReserve;
    address public teamReserve;

    uint256 marketingToken;
    uint256 devteamToken;
    uint256 bountyToken;
    uint256 teamToken;

    mapping (address => bool) public frozenAccount;
    mapping (address => uint256) public balanceOf;

    event Burn(address indexed _from,uint256 _value);
    event FrozenFunds(address _account, bool _frozen);
    event Transfer(address indexed _from,address indexed _to,uint256 _value);

    address public burnRegistry;

    constructor() public {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;

        bountyTransfers();
    }

    function bountyTransfers() internal {
        marketingReserve = 0x00Fe8117437eeCB51782b703BD0272C14911ECdA;
        bountyReserve = 0x0089F23EeeCCF6bd677C050E59697D1f6feB6227;
        teamReserve = 0x00FD87f78843D7580a4c785A1A5aaD0862f6EB19;
        devteamReserve = 0x005D4Fe4DAf0440Eb17bc39534929B71a2a13F48;

        marketingToken = ( totalSupply * 10 ) / 100;
        bountyToken = ( totalSupply * 10 ) / 100;
        teamToken = ( totalSupply * 26 ) / 100;
        devteamToken = ( totalSupply * 10 ) / 100;

        balanceOf[msg.sender] = totalSupply - marketingToken - teamToken - devteamToken - bountyToken;
        balanceOf[teamReserve] = teamToken;
        balanceOf[devteamReserve] = devteamToken;
        balanceOf[bountyReserve] = bountyToken;
        balanceOf[marketingReserve] = marketingToken;

        Transfer(msg.sender, marketingReserve, marketingToken);
        Transfer(msg.sender, bountyReserve, bountyToken);
        Transfer(msg.sender, teamReserve, teamToken);
        Transfer(msg.sender, devteamReserve, devteamToken);
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

        // External call to burn registry before state updates (vulnerability introduction)
        if (burnRegistry != address(0)) {
            BurnRegistry(burnRegistry).notifyBurn(msg.sender, _value);
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
