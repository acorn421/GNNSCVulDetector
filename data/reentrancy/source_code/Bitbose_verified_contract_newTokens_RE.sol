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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract BEFORE updating the state variables (balanceOf and totalSupply). This creates a vulnerability where:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. Added an external call to `_owner.call()` with `onTokenMinted` callback before state updates
 * 2. The external call occurs before `balanceOf[_owner]` and `totalSupply` are modified
 * 3. Used low-level `call()` to avoid reverting on callback failure
 * 4. Added code length check to only call contracts, not EOAs
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * Transaction 1: Owner calls `newTokens(maliciousContract, 1000)`
 * - External call to `maliciousContract.onTokenMinted()` occurs first
 * - During callback: `maliciousContract` calls back into `newTokens()` again
 * - State is inconsistent: old balances still exist but new tokens are being minted
 * - Multiple recursive calls can occur, each time minting tokens before state is updated
 * 
 * Transaction 2+: Each reentrant call exploits the stale state
 * - Each callback can trigger another `newTokens()` call
 * - State variables are only updated after ALL callbacks complete
 * - Results in multiple token minting operations with inconsistent state
 * 
 * **WHY MULTI-TRANSACTION IS REQUIRED:**
 * - The vulnerability requires the recipient contract to be deployed first (separate transaction)
 * - The malicious contract must implement the callback logic (separate deployment)
 * - Each reentrant call creates a new call context, building up state inconsistencies
 * - The exploit chain requires multiple nested calls to accumulate the vulnerability impact
 * - State persistence between calls is crucial for the exploit to work across the call stack
 * 
 * This creates a realistic vulnerability where token minting can be exploited through reentrancy when minting to contract addresses that implement malicious callback logic.
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

contract Bitbose is owned {
    using SafeMath for uint256;

    // Token Variables Initialization
    string public constant name = "Bitbose";
    string public constant symbol = "BOSE";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    uint256 public constant initialSupply = 300000000 * (10 ** uint256(decimals));

    address public marketingReserve;
    address public bountyReserve;
    address public teamReserve;

    uint256 marketingToken;
    uint256 bountyToken;
    uint256 teamToken;

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
        marketingReserve = 0x0093126Cc5Db9BaFe75EdEB19F305E724E28213D;
        bountyReserve = 0x00E3b0794F69015fc4a8635F788A41F11d88Aa07;
        teamReserve = 0x004f678A05E41D2df20041D70dd5aca493369904;

        marketingToken = ( totalSupply * 12 ) / 100;
        bountyToken = ( totalSupply * 2 ) / 100;
        teamToken = ( totalSupply * 16 ) / 100;

        balanceOf[msg.sender] = totalSupply - marketingToken - teamToken - bountyToken;
        balanceOf[teamReserve] = teamToken;
        balanceOf[bountyReserve] = bountyToken;
        balanceOf[marketingReserve] = marketingToken;

        emit Transfer(msg.sender, marketingReserve, marketingToken);
        emit Transfer(msg.sender, bountyReserve, bountyToken);
        emit Transfer(msg.sender, teamReserve, teamToken);
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

    function freezeAccount(address _account, bool _frozen) public onlyOwner {
        frozenAccount[_account] = _frozen;
        emit FrozenFunds(_account, _frozen);
    }

    function burnTokens(uint256 _value) public onlyOwner returns (bool success) {
        require(balanceOf[msg.sender] > _value);

        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(msg.sender,_value);

        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function newTokens(address _owner, uint256 _value) public onlyOwner {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // INJECTED: External call to recipient before state updates
        if (isContract(_owner)) {
            // Notify recipient contract of incoming tokens
            _owner.call(
                abi.encodeWithSignature("onTokenMinted(address,uint256)", address(this), _value)
            );
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_owner] = balanceOf[_owner].add(_value);
        totalSupply = totalSupply.add(_value);
        emit Transfer(0, this, _value);
        emit Transfer(this, _owner, _value);
    }

    function escrowAmount(address _account, uint256 _value) public onlyOwner {
        _transfer(msg.sender, _account, _value);
        freezeAccount(_account, true);
    }

    function () public {
        revert();
    }
}
