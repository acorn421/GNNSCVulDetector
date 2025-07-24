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
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack by adding an external call to a user-controlled burn observer contract before the internal _burn function is called. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnObserver(burnObserver).onBurnStarted(msg.sender, _value)` before the state-modifying `_burn` function
 * 2. The external call allows a malicious observer contract to re-enter the burn function during the callback
 * 3. This creates a window where the function can be re-entered before the burn state updates are completed
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker sets up a malicious burn observer contract that implements IBurnObserver
 * 2. **Transaction 2**: Owner calls burn() with a specific value
 * 3. **During Transaction 2**: The external call triggers the malicious observer's onBurnStarted() callback
 * 4. **Reentrancy Attack**: The malicious observer re-enters burn() with different parameters during the callback
 * 5. **State Manipulation**: Since _burn() hasn't been called yet in the original context, the attacker can manipulate the burn process, potentially:
 *    - Burning more tokens than intended by calling burn multiple times before state updates
 *    - Manipulating the burnedSupply counter through multiple nested calls
 *    - Exploiting the burnFinished flag state transitions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker needs separate transactions to set up the malicious observer contract
 * - The vulnerability only manifests when the burn function is called after the malicious observer is in place
 * - The exploit depends on the accumulated state from previous burn operations (burnedSupply counter)
 * - The burnFinished flag state can be manipulated across multiple burn operations, requiring a sequence of calls to reach the vulnerable state
 * 
 * **State Persistence Exploitation:**
 * - The burnedSupply counter persists between transactions and can be manipulated
 * - The burnFinished flag state can be bypassed through reentrancy
 * - Multiple nested calls can occur before the original burn completes, leading to inconsistent state
 */
pragma solidity ^0.4.25;

interface IBurnObserver {
    function onBurnStarted(address burner, uint256 value) external;
}

library Math {
    function sub(uint256 _a, uint256 _b) internal pure returns (uint256) {
        assert(_b <= _a);
        return _a - _b;
    }
    function add(uint256 _a, uint256 _b) internal pure returns (uint256 c) {
        c = _a + _b;
        assert(c >= _a);
        return c;
    }
}

contract MCCToken {
    using Math for uint256;

    string public name = "Material Connection Coin";  //代币名称
    string public symbol = "MCC"; //代币标识
    uint8  public decimals = 15; //代币位数
    uint256 public totalSupply = 160000000 * 10 ** uint256(decimals); //代币发行总量
 
    mapping (address => uint256) public balanceOf; //代币存储
	address public owner; //合约所有者
	
	bool public burnFinished = false;  //TRUE代币停止销毁
	uint256 public burnedSupply = 0; //已销毁在代币数
	uint256 public burnedLimit = 60000000 * 10 ** uint256(decimals); //销毁代币到6千万,停止销毁
	
	bool public mintingFinished = false; //TRUE代币停止增发

    address public burnObserver;

    constructor() public {
        balanceOf[msg.sender] = totalSupply;
		owner = msg.sender;
    }

	modifier onlyOwner() {
		require(msg.sender == owner);
		 _;
	}

	modifier canBurn() {
		require(!burnFinished);
		 _;
	}
	
	modifier canMint() {
		require(!mintingFinished);
		 _;
	}

	event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed burner, uint256 value);
	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
	event Mint(address indexed to, uint256 amount);
    event MintFinished();

	function _transferOwnership(address _newOwner) internal {
		require(_newOwner != address(0));
		emit OwnershipTransferred(owner, _newOwner);
		owner = _newOwner;
	}
	
	//转移合约所有权到另一个账户
	function transferOwnership(address _newOwner) public onlyOwner {
		_transferOwnership(_newOwner);
	}

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0); 
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);

        uint previousBalances = balanceOf[_from] + balanceOf[_to];

        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);

        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    //代币转账
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function _burn(address _who, uint256 _value) internal {
        require(_value <= balanceOf[_who]);
        
        uint256 burnAmount = _value;

        //最后一笔销毁数量+已销毁数量>销毁上限，则最后一笔销毁数=销毁上限-已销毁数量
		if (burnAmount.add(burnedSupply) > burnedLimit){
			burnAmount = burnedLimit.sub(burnedSupply);
		}

        balanceOf[_who] = balanceOf[_who].sub(burnAmount);
        totalSupply = totalSupply.sub(burnAmount);
		burnedSupply = burnedSupply.add(burnAmount);
		
		//代币销毁到6千万时，平台将停止回购
		if (burnedSupply >= burnedLimit) {
			burnFinished = true;
		}
		
        emit Burn(_who, burnAmount);
        emit Transfer(_who, address(0), burnAmount);
    }

    //代币销毁,减少发行总量
    function burn(uint256 _value) public onlyOwner canBurn {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify burn observers before state updates
        if (burnObserver != address(0)) {
            IBurnObserver(burnObserver).onBurnStarted(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _burn(msg.sender, _value);
    }
	
	//代币增发
	function mint(address _to, uint256 _amount) public onlyOwner canMint returns (bool){
		totalSupply = totalSupply.add(_amount);
		balanceOf[_to] = balanceOf[_to].add(_amount);
		emit Mint(_to, _amount);
		return true;
	}
	
	//代币停止增发
	function finishMinting() onlyOwner canMint public returns (bool) {
		mintingFinished = true;
		emit MintFinished();
		return true;
	}

}
