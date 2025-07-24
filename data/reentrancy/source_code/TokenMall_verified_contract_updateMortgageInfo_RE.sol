/*
 * ===== SmartInject Injection Details =====
 * Function      : updateMortgageInfo
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to validation and notification services around state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Multi-Transaction Exploitation Mechanism**: An attacker controlling the validationService or notificationService contracts can exploit this vulnerability across multiple transactions by:
 *    - Transaction 1: Call updateMortgageInfo with a malicious validation/notification contract
 *    - Transaction 2: During the external call, the malicious contract can call back into updateMortgageInfo
 *    - Transaction 3+: Continue the reentrancy pattern to manipulate state inconsistently
 * 
 * 2. **State Accumulation Dependency**: The vulnerability becomes exploitable only after multiple legitimate updates have been made to different projects, creating a state where:
 *    - Multiple project IDs exist in the system
 *    - The mortgageInfos array contains accumulated entries from previous transactions
 *    - The attacker can manipulate the order and timing of updates across different projects
 * 
 * 3. **Stateful Exploitation Pattern**: The reentrancy allows manipulation of the mortgageInfos array and mInfo mapping in ways that require previous state accumulation:
 *    - An attacker can cause duplicate entries in mortgageInfos array through reentrancy
 *    - The vulnerability enables manipulation of release amounts across multiple projects in a single attack sequence
 *    - The exploit requires existing project data from previous transactions to be effective
 * 
 * 4. **Realistic Integration Points**: The external calls to validation and notification services are realistic additions that would naturally appear in production mortgage management systems, making the vulnerability subtle and believable.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the accumulated state from previous updateMortgageInfo calls and the ability to manipulate that state through carefully orchestrated reentrancy across multiple transaction boundaries.
 */
pragma solidity ^0.4.22;
contract Ownable {
  address public owner;

  event OwnershipRenounced(address indexed previousOwner);
  event OwnershipTransferred(
    address indexed previousOwner,
    address indexed newOwner
  );

  /**
   * @dev 可拥有的构造函数将合同的原始“所有者”设置为发送者
   * account.
   */
  constructor() public {
    owner = msg.sender;
  }

  /**
   * @dev 如果由所有者以外的任何帐户调用，则抛出
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev 允许业主放弃合同的控制权.
   */
  function renounceOwnership() public onlyOwner {
    emit OwnershipRenounced(owner);
    owner = address(0);
  }

  /**
   * @dev 允许当前所有者将合同的控制转移给新所有者.
   */
  function transferOwnership(address _newOwner) public onlyOwner {
    _transferOwnership(_newOwner);
  }

  /**
   * @dev 将合同的控制权移交给新所有者.
   */
  function _transferOwnership(address _newOwner) internal {
    require(_newOwner != address(0));
    emit OwnershipTransferred(owner, _newOwner);
    owner = _newOwner;
  }
}

contract TokenMall is Ownable {
  /**
   * @dev 抵押物上链信息.
   */
  struct MortgageInfo {
      bytes32 projectId;//项目ID 
      string currency;//抵押币种 
      string mortgageAmount;//抵押数量 
      string releaseAmount;//释放数量 
  }
  mapping(bytes32 =>MortgageInfo) mInfo;
  bytes32[] mortgageInfos;
  
  /**
   * @dev 添加数据.
   */
    event MessageMintInfo(address sender,bool isScuccess,string message);
    function mintMortgageInfo(string _projectId,string currency,string mortgageAmount,string releaseAmount) public onlyOwner {
        bytes32 proId = stringToBytes32(_projectId);
        if(mInfo[proId].projectId != proId){
              mInfo[proId].projectId = proId;
              mInfo[proId].currency = currency;
              mInfo[proId].mortgageAmount = mortgageAmount;
              mInfo[proId].releaseAmount = releaseAmount;
              mortgageInfos.push(proId);
              MessageMintInfo(msg.sender, true,"添加成功");
            return;
        }else{
             MessageMintInfo(msg.sender, false,"项目ID已经存在");
            return;
        }
    }
  /**
   * @dev 更新数据.
   */
    event MessageUpdateInfo(address sender,bool isScuccess,string message);

    // Define interfaces for external services referenced in vulnerability
    // These are injected to preserve the external call vulnerability as in the original code
    // Placeholders for demonstration
    ValidationService validationService;
    NotificationService notificationService;
    
    function updateMortgageInfo(string _projectId,string releaseAmount) public onlyOwner {
         bytes32 proId = stringToBytes32(_projectId);
        if(mInfo[proId].projectId == proId){
              // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
              // External call to validation service before state updates
              if(address(validationService) != address(0)) {
                  validationService.validateReleaseAmount(proId, releaseAmount);
              }
              
              // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
              mInfo[proId].releaseAmount = releaseAmount;
              mortgageInfos.push(proId);
              // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
              
              // Additional external call to notify stakeholders after partial state update
              if(address(notificationService) != address(0)) {
                  notificationService.notifyReleaseUpdate(proId, releaseAmount);
              }
              
              // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
              MessageUpdateInfo(msg.sender, true,"修改成功");
            return;
        }else{
             MessageUpdateInfo(msg.sender, false,"项目ID不存在");
            return;
        }
    }

    /// string类型转化为bytes32型转
    function stringToBytes32(string memory source) internal constant returns(bytes32 result){
        assembly{
            result := mload(add(source,32))
        }
    }
    /// bytes32类型转化为string型转
    function bytes32ToString(bytes32 x) internal constant returns(string){
        bytes memory bytesString = new bytes(32);
        uint charCount = 0 ;
        for(uint j = 0 ; j<32;j++){
            byte char = byte(bytes32(uint(x) *2 **(8*j)));
            if(char !=0){
                bytesString[charCount] = char;
                charCount++;
            }
        }
        bytes memory bytesStringTrimmed = new bytes(charCount);
        for(j=0;j<charCount;j++){
            bytesStringTrimmed[j]=bytesString[j];
        }
        return string(bytesStringTrimmed);
    }
}

// Placeholders for vulnerable external services (interfaces must be declared for compilation)
contract ValidationService {
    function validateReleaseAmount(bytes32, string) public;
}
contract NotificationService {
    function notifyReleaseUpdate(bytes32, string) public;
}
