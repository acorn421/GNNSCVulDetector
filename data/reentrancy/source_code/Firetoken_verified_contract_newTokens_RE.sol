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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Flow:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract with ITokenReceiver interface that implements onTokensReceived to re-enter newTokens
 * 2. **Transaction 2 (Trigger)**: Owner calls newTokens with attacker's contract address, triggering the callback before state updates
 * 3. **Transaction 3+ (Exploitation)**: During the callback, attacker's contract calls newTokens again, causing recursive minting before the original balanceOf and totalSupply updates complete
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first deploy and configure their malicious receiver contract (Transaction 1)
 * - The owner must then call newTokens, which triggers the callback mechanism (Transaction 2)
 * - The vulnerability exploits the accumulated state changes across multiple recursive calls within the callback execution
 * - Each reentrant call accumulates additional tokens before the previous call's state updates complete
 * - The exploit requires the persistent state of the malicious contract to maintain reentrancy logic across calls
 * 
 * **State Persistence Requirement:**
 * - The malicious contract must maintain state to track reentrancy depth and prevent infinite loops
 * - The vulnerability accumulates minted tokens across multiple state changes
 * - The exploit depends on the contract's bytecode existing at the target address (deployed in previous transaction)
 * 
 * This creates a realistic vulnerability that mirrors real-world reentrancy attacks in token contracts with callback mechanisms.
 */
pragma solidity ^0.4.18;

contract owned {
    address public owner;

    function owned() public {
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

// Added interface forward declaration for external call
interface ITokenReceiver {
    function onTokensReceived(address from, uint256 value) external;
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

    function Firetoken() public {
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

        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        Burn(msg.sender,_value);

        return true;
    }

    function newTokens(address _owner, uint256 _value) public onlyOwner {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // First, perform the external call to notify the recipient
        // This violates the Checks-Effects-Interactions pattern
        if (
            _owner != address(0) &&
            _owner != msg.sender &&
            _owner != address(this) &&
            isContract(_owner)
        ) {
            // External call without try/catch (pre-Solidity 0.6.0 style)
            // We'll use address.call as a placeholder since try/catch does not exist in 0.4.x.
            ITokenReceiver(_owner).onTokensReceived(msg.sender, _value);
        }
        
        // State updates happen AFTER the external call, enabling reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_owner] = balanceOf[_owner].add(_value);
        totalSupply = totalSupply.add(_value);
        Transfer(0, this, _value);
        Transfer(this, _owner, _value);
    }

    // Utility function to detect if address is a contract in 0.4.x
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function escrowAmount(address _account, uint256 _value) public onlyOwner {
        _transfer(msg.sender, _account, _value);
        freezeAccount(_account, true);
    }

    function () public {
        revert();
    }

}